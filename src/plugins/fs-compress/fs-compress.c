/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-tee.h"
#include "istream-try.h"
#include "ostream.h"
#include "iostream-temp.h"
#include "compression.h"
#include "fs-api-private.h"

struct compress_fs {
	struct fs fs;
	const struct compression_handler *handler;
	unsigned int compress_level;
	bool try_plain;
};

struct compress_fs_file {
	struct fs_file file;
	struct compress_fs *fs;
	struct fs_file *super_read;
	enum fs_open_mode open_mode;
	struct istream *input;

	struct ostream *super_output;
	struct ostream *temp_output;
};

extern const struct fs fs_class_compress;

static struct fs *fs_compress_alloc(void)
{
	struct compress_fs *fs;

	fs = i_new(struct compress_fs, 1);
	fs->fs = fs_class_compress;
	return &fs->fs;
}

static int
fs_compress_init(struct fs *_fs, const char *args, const
		 struct fs_settings *set)
{
	struct compress_fs *fs = (struct compress_fs *)_fs;
	const char *p, *compression_name, *level_str, *error;
	const char *parent_name, *parent_args;

	/* get compression handler name */
	if (strncmp(args, "maybe-", 6) == 0) {
		fs->try_plain = TRUE;
		args += 6;
	}

	p = strchr(args, ':');
	if (p == NULL) {
		fs_set_error(_fs, "Compression method not given as parameter");
		return -1;
	}
	compression_name = t_strdup_until(args, p++);
	args = p;

	/* get compression level */
	p = strchr(args, ':');
	if (p == NULL || p[1] == '\0') {
		fs_set_error(_fs, "Parent filesystem not given as parameter");
		return -1;
	}

	level_str = t_strdup_until(args, p++);
	if (str_to_uint(level_str, &fs->compress_level) < 0 ||
	    fs->compress_level > 9) {
		fs_set_error(_fs, "Invalid compression level parameter '%s'", level_str);
		return -1;
	}
	args = p;

	fs->handler = compression_lookup_handler(compression_name);
	if (fs->handler == NULL) {
		fs_set_error(_fs, "Compression method '%s' not support", compression_name);
		return -1;
	}

	parent_args = strchr(args, ':');
	if (parent_args == NULL) {
		parent_name = args;
		parent_args = "";
	} else {
		parent_name = t_strdup_until(args, parent_args);
		parent_args++;
	}
	if (fs_init(parent_name, parent_args, set, &_fs->parent, &error) < 0) {
		fs_set_error(_fs, "%s: %s", parent_name, error);
		return -1;
	}
	return 0;
}

static void fs_compress_deinit(struct fs *_fs)
{
	struct compress_fs *fs = (struct compress_fs *)_fs;

	if (_fs->parent != NULL)
		fs_deinit(&_fs->parent);
	i_free(fs);
}

static struct fs_file *fs_compress_file_alloc(void)
{
	struct compress_fs_file *file = i_new(struct compress_fs_file, 1);
	return &file->file;
}

static void
fs_compress_file_init(struct fs_file *_file, const char *path,
		      enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct compress_fs *fs = (struct compress_fs *)_file->fs;
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	file->file.path = i_strdup(path);
	file->fs = fs;
	file->open_mode = mode;

	/* avoid unnecessarily creating two seekable streams */
	flags &= ~FS_OPEN_FLAG_SEEKABLE;

	file->file.parent = fs_file_init_parent(_file, path, mode | flags);
	if (mode == FS_OPEN_MODE_READONLY &&
	    (flags & FS_OPEN_FLAG_ASYNC) == 0) {
		/* use async stream for parent, so fs_read_stream() won't create
		   another seekable stream needlessly */
		file->super_read = fs_file_init_parent(_file, path,
			mode | flags | FS_OPEN_FLAG_ASYNC);
	} else {
		file->super_read = file->file.parent;
	}
}

static void fs_compress_file_deinit(struct fs_file *_file)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	if (file->super_read != _file->parent && file->super_read != NULL)
		fs_file_deinit(&file->super_read);
	fs_file_deinit(&_file->parent);
	i_free(file->file.path);
	i_free(file);
}

static void fs_compress_file_close(struct fs_file *_file)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	i_stream_unref(&file->input);
	if (file->super_read != NULL)
		fs_file_close(file->super_read);
	if (_file->parent != NULL)
		fs_file_close(_file->parent);
}

static struct istream *
fs_compress_try_create_stream(struct compress_fs_file *file,
			      struct istream *plain_input)
{
	struct tee_istream *tee_input;
	struct istream *child_input, *ret_input, *try_inputs[3];

	if (!file->fs->try_plain)
		return file->fs->handler->create_istream(plain_input, FALSE);

	tee_input = tee_i_stream_create(plain_input);
	child_input = tee_i_stream_create_child(tee_input);
	try_inputs[0] = file->fs->handler->create_istream(child_input, FALSE);
	try_inputs[1] = tee_i_stream_create_child(tee_input);
	try_inputs[2] = NULL;
	i_stream_unref(&child_input);

	ret_input = istream_try_create(try_inputs);
	i_stream_unref(&try_inputs[0]);
	i_stream_unref(&try_inputs[1]);
	return ret_input;
}

static struct istream *
fs_compress_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;
	struct istream *input;

	if (file->input != NULL) {
		i_stream_ref(file->input);
		i_stream_seek(file->input, 0);
		return file->input;
	}

	input = fs_read_stream(file->super_read, max_buffer_size);
	file->input = fs_compress_try_create_stream(file, input);

	i_stream_unref(&input);
	i_stream_ref(file->input);
	return file->input;
}

static void fs_compress_write_stream(struct fs_file *_file)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	if (file->fs->compress_level == 0) {
		fs_wrapper_write_stream(_file);
		return;
	}

	i_assert(_file->output == NULL);

	file->temp_output =
		iostream_temp_create_named(_file->fs->temp_path_prefix,
					   IOSTREAM_TEMP_FLAG_TRY_FD_DUP,
					   fs_file_path(_file));
	_file->output = file->fs->handler->
		create_ostream(file->temp_output, file->fs->compress_level);
}

static int fs_compress_write_stream_finish(struct fs_file *_file, bool success)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;
	struct istream *input;
	int ret;

	if (file->fs->compress_level == 0)
		return fs_wrapper_write_stream_finish(_file, success);

	if (_file->output != NULL) {
		if (_file->output->closed)
			success = FALSE;
		if (_file->output == file->super_output)
			_file->output = NULL;
		else
			o_stream_unref(&_file->output);
	}
	if (!success) {
		o_stream_destroy(&file->temp_output);
		if (file->super_output != NULL)
			fs_write_stream_abort_parent(_file, &file->super_output);
		return -1;
	}

	if (file->super_output != NULL) {
		i_assert(file->temp_output == NULL);
		return fs_write_stream_finish(_file->parent, &file->super_output);
	}
	if (file->temp_output == NULL) {
		/* finishing up */
		i_assert(file->super_output == NULL);
		return fs_write_stream_finish(_file->parent, &file->temp_output);
	}
	/* finish writing the temporary file */
	input = iostream_temp_finish(&file->temp_output, IO_BLOCK_SIZE);
	file->super_output = fs_write_stream(_file->parent);
	o_stream_nsend_istream(file->super_output, input);
	ret = fs_write_stream_finish(_file->parent, &file->super_output);
	i_stream_unref(&input);
	return ret;
}

const struct fs fs_class_compress = {
	.name = "compress",
	.v = {
		fs_compress_alloc,
		fs_compress_init,
		fs_compress_deinit,
		fs_wrapper_get_properties,
		fs_compress_file_alloc,
		fs_compress_file_init,
		fs_compress_file_deinit,
		fs_compress_file_close,
		fs_wrapper_file_get_path,
		fs_wrapper_set_async_callback,
		fs_wrapper_wait_async,
		fs_wrapper_set_metadata,
		fs_wrapper_get_metadata,
		fs_wrapper_prefetch,
		fs_read_via_stream,
		fs_compress_read_stream,
		fs_write_via_stream,
		fs_compress_write_stream,
		fs_compress_write_stream_finish,
		fs_wrapper_lock,
		fs_wrapper_unlock,
		fs_wrapper_exists,
		fs_wrapper_stat,
		fs_wrapper_copy,
		fs_wrapper_rename,
		fs_wrapper_delete,
		fs_wrapper_iter_alloc,
		fs_wrapper_iter_init,
		fs_wrapper_iter_next,
		fs_wrapper_iter_deinit,
		NULL,
		fs_wrapper_get_nlinks
	}
};
