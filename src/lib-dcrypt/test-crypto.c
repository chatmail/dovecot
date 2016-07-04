#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "dcrypt.h"
#include "ostream.h"
#include "ostream-encrypt.h"
#include "istream.h"
#include "istream-decrypt.h"
#include "iostream-temp.h"
#include "randgen.h"
#include "test-common.h"
#include "hex-binary.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>


static
void test_cipher_test_vectors(void)
{
	static struct {
		const char *key;
		const char *iv;
		const char *pt;
		const char *ct;
	} vectors[] =
	{
		{ "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "7649abac8119b246cee98e9b12e9197d" },
		{ "2b7e151628aed2a6abf7158809cf4f3c", "7649ABAC8119B246CEE98E9B12E9197D", "ae2d8a571e03ac9c9eb76fac45af8e51", "5086cb9b507219ee95db113a917678b2" }
	};


	test_begin("test_cipher_test_vectors");

	buffer_t *key,*iv,*pt,*ct,*res_enc,*res_dec;

	key = buffer_create_dynamic(pool_datastack_create(), 16);
	iv = buffer_create_dynamic(pool_datastack_create(), 16);
	pt = buffer_create_dynamic(pool_datastack_create(), 16);
	ct = buffer_create_dynamic(pool_datastack_create(), 16);

	res_enc = buffer_create_dynamic(pool_datastack_create(), 32);
	res_dec = buffer_create_dynamic(pool_datastack_create(), 32);

	for(size_t i = 0; i < N_ELEMENTS(vectors); i++) {
		struct dcrypt_context_symmetric *ctx;

		buffer_set_used_size(key, 0);
		buffer_set_used_size(iv, 0);
		buffer_set_used_size(pt, 0);
		buffer_set_used_size(ct, 0);
		buffer_set_used_size(res_enc, 0);
		buffer_set_used_size(res_dec, 0);

		hex_to_binary(vectors[i].key, key);
		hex_to_binary(vectors[i].iv, iv);
		hex_to_binary(vectors[i].pt, pt);
		hex_to_binary(vectors[i].ct, ct);

		if (!dcrypt_ctx_sym_create("AES-128-CBC", DCRYPT_MODE_ENCRYPT, &ctx, NULL)) {
			test_assert_failed("dcrypt_ctx_sym_create", __FILE__, __LINE__-1);
			continue;
		}

		dcrypt_ctx_sym_set_padding(ctx, FALSE);

		dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
		dcrypt_ctx_sym_set_iv(ctx, iv->data, iv->used);

		test_assert_idx(dcrypt_ctx_sym_init(ctx, NULL), i);

		test_assert_idx(dcrypt_ctx_sym_update(ctx, pt->data, pt->used, res_enc, NULL), i);
		test_assert_idx(dcrypt_ctx_sym_final(ctx, res_enc, NULL), i);

		test_assert_idx(buffer_cmp(ct, res_enc), i);

		dcrypt_ctx_sym_destroy(&ctx);

		if (!dcrypt_ctx_sym_create("AES-128-CBC", DCRYPT_MODE_DECRYPT, &ctx, NULL)) {
			test_assert_failed("dcrypt_ctx_sym_create", __FILE__, __LINE__-1);
			continue;
		}

		dcrypt_ctx_sym_set_padding(ctx, FALSE);

		dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
		dcrypt_ctx_sym_set_iv(ctx, iv->data, iv->used);

		test_assert_idx(dcrypt_ctx_sym_init(ctx, NULL), i);
		test_assert_idx(dcrypt_ctx_sym_update(ctx, res_enc->data, res_enc->used, res_dec, NULL), i);
		test_assert_idx(dcrypt_ctx_sym_final(ctx, res_dec, NULL), i);

		test_assert_idx(buffer_cmp(pt, res_dec), i);

		dcrypt_ctx_sym_destroy(&ctx);
	}

	test_end();
}

static
void test_cipher_aead_test_vectors(void)
{
	struct dcrypt_context_symmetric *ctx;
	const char *error = NULL;

	test_begin("test_cipher_aead_test_vectors");

	if (!dcrypt_ctx_sym_create("aes-128-gcm", DCRYPT_MODE_ENCRYPT, &ctx, &error)) {
		test_assert_failed("dcrypt_ctx_sym_create", __FILE__, __LINE__-1);
		return;
	}

	buffer_t *key, *iv, *aad, *pt, *ct, *tag, *tag_res, *res;

	key = buffer_create_dynamic(pool_datastack_create(), 16);
	iv = buffer_create_dynamic(pool_datastack_create(), 16);
	aad = buffer_create_dynamic(pool_datastack_create(), 16);
	pt = buffer_create_dynamic(pool_datastack_create(), 16);
	ct = buffer_create_dynamic(pool_datastack_create(), 16);
	tag = buffer_create_dynamic(pool_datastack_create(), 16);
	res = buffer_create_dynamic(pool_datastack_create(), 16);
	tag_res = buffer_create_dynamic(pool_datastack_create(), 16);

	hex_to_binary("feffe9928665731c6d6a8f9467308308", key);
	hex_to_binary("cafebabefacedbaddecaf888", iv);
	hex_to_binary("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", pt);
	hex_to_binary("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", ct);
	hex_to_binary("4d5c2af327cd64a62cf35abd2ba6fab4", tag);

	dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
	dcrypt_ctx_sym_set_iv(ctx, iv->data, iv->used);
	dcrypt_ctx_sym_set_aad(ctx, aad->data, aad->used);
	test_assert(dcrypt_ctx_sym_init(ctx, &error));
	test_assert(dcrypt_ctx_sym_update(ctx, pt->data, pt->used, res, &error));
	test_assert(dcrypt_ctx_sym_final(ctx, res, &error));
	test_assert(dcrypt_ctx_sym_get_tag(ctx, tag_res));

	test_assert(buffer_cmp(ct, res) == TRUE);
	test_assert(buffer_cmp(tag, tag_res) == TRUE);

	dcrypt_ctx_sym_destroy(&ctx);

	if (!dcrypt_ctx_sym_create("aes-128-gcm", DCRYPT_MODE_DECRYPT, &ctx, &error)) {
		test_assert_failed("dcrypt_ctx_sym_create", __FILE__, __LINE__-1);
	} else {

		buffer_set_used_size(res, 0);

		dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
		dcrypt_ctx_sym_set_iv(ctx, iv->data, iv->used);
		dcrypt_ctx_sym_set_aad(ctx, aad->data, aad->used);
		dcrypt_ctx_sym_set_tag(ctx, tag->data, tag->used);
		test_assert(dcrypt_ctx_sym_init(ctx, &error));
		test_assert(dcrypt_ctx_sym_update(ctx, ct->data, ct->used, res, &error));
		test_assert(dcrypt_ctx_sym_final(ctx, res, &error));

		test_assert(buffer_cmp(pt, res) == TRUE);

		dcrypt_ctx_sym_destroy(&ctx);
	}

	test_end();
}

static
void test_hmac_test_vectors(void)
{
	test_begin("test_hmac_test_vectors");

	buffer_t *pt, *ct, *key, *res;
	pt = buffer_create_dynamic(pool_datastack_create(), 50);
	key = buffer_create_dynamic(pool_datastack_create(), 20);
	ct = buffer_create_dynamic(pool_datastack_create(), 32);
	res = buffer_create_dynamic(pool_datastack_create(), 32);

	hex_to_binary("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key);
	hex_to_binary("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", pt);
	hex_to_binary("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", res);

	struct dcrypt_context_hmac *hctx;
	if (!dcrypt_ctx_hmac_create("sha256", &hctx, NULL)) {
		test_assert_failed("dcrypt_ctx_hmac_create", __FILE__, __LINE__-1);
	} else {
		dcrypt_ctx_hmac_set_key(hctx, key->data, key->used);
		test_assert(dcrypt_ctx_hmac_init(hctx, NULL));
		test_assert(dcrypt_ctx_hmac_update(hctx, pt->data, pt->used, NULL));
		test_assert(dcrypt_ctx_hmac_final(hctx, ct, NULL));
		test_assert(buffer_cmp(ct, res));
		dcrypt_ctx_hmac_destroy(&hctx);
	}

	test_end();
}

static
void test_load_v1_keys(void)
{
	test_begin("test_load_v1_keys");

	const char *error = NULL;
	const char *data1 = "1\t716\t1\t0567e6bf9579813ae967314423b0fceb14bda24749303923de9a9bb9370e0026f995901a57e63113eeb2baf0c940e978d00686cbb52bd5014bc318563375876255\t0300E46DA2125427BE968EB3B649910CDC4C405E5FFDE18D433A97CABFEE28CEEFAE9EE356C792004FFB80981D67E741B8CC036A34235A8D2E1F98D1658CFC963D07EB\td0cfaca5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd433615e77a0\t7c9a1039ea2e4fed73e81dd3ffc3fa22ea4a28352939adde7bf8ea858b00fa4f";

	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type encryption_type;
	const char *encryption_key_hash = NULL;
	const char *key_hash = NULL;

	bool ret = dcrypt_key_string_get_info(data1, &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);

	test_assert(ret == TRUE);
	test_assert(error == NULL);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_1);
	test_assert(kind == DCRYPT_KEY_KIND_PRIVATE);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_KEY);
	test_assert(strcmp(encryption_key_hash, "d0cfaca5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd433615e77a0") == 0);
	test_assert(strcmp(key_hash, "7c9a1039ea2e4fed73e81dd3ffc3fa22ea4a28352939adde7bf8ea858b00fa4f") == 0);

	const char* data2 = "1\t716\t0301EB00973C4EFC8FCECA4EA33E941F50B561199A5159BCB6C2EED9DD1D62D65E38A254979D89E28F0C28883E71EE2AD264CD16B863FA094A8F6F69A56B62E8918040\t7c9a1039ea2e4fed73e81dd3ffc3fa22ea4a28352939adde7bf8ea858b00fa4f";

	error = NULL;
	encryption_key_hash = NULL;
	key_hash = NULL;

	ret = dcrypt_key_string_get_info(data2, &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);

	test_assert(ret == TRUE);
	test_assert(error == NULL);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_1);
	test_assert(kind == DCRYPT_KEY_KIND_PUBLIC);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(encryption_key_hash == NULL);
	test_assert(strcmp(key_hash, "7c9a1039ea2e4fed73e81dd3ffc3fa22ea4a28352939adde7bf8ea858b00fa4f") == 0);

	/* This is the key that should be able to decrypt key1 */
	const char *data3 = "1\t716\t0\t048FD04FD3612B22D32790C592CF21CEF417EFD2EA34AE5F688FA5B51BED29E05A308B68DA78E16E90B47A11E133BD9A208A2894FD01B0BEE865CE339EA3FB17AC\td0cfaca5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd433615e77a0";

	error = NULL;
	encryption_key_hash = NULL;
	key_hash = NULL;

	ret = dcrypt_key_string_get_info(data3, &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);
	test_assert(ret == TRUE);
	test_assert(error == NULL);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_1);
	test_assert(kind == DCRYPT_KEY_KIND_PRIVATE);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(encryption_key_hash == NULL);
	test_assert(strcmp(key_hash, "d0cfaca5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd433615e77a0") == 0);

	/* key3's key_hash should and does match key1's encryption_key_hash */
	struct dcrypt_private_key *pkey = NULL;
	struct dcrypt_private_key *pkey2 = NULL;
	pkey = NULL;
	error = NULL;

	ret = dcrypt_key_load_private(&pkey2, format, data3, NULL, NULL, &error);
	test_assert(ret == TRUE);
	test_assert(error == NULL);

	ret = dcrypt_key_load_private(&pkey, format, data1, NULL, pkey2, &error);
	test_assert(ret == TRUE);
	test_assert(error == NULL);

	dcrypt_key_free_private(&pkey2);
	dcrypt_key_free_private(&pkey);

	test_end();
}

static
void test_load_v1_key(void)
{
	test_begin("test_load_v1_key");

	buffer_t *key_1 = buffer_create_dynamic(pool_datastack_create(), 128);

	struct dcrypt_private_key *pkey = NULL, *pkey2 = NULL;
	const char *error = NULL;

	test_assert(dcrypt_key_load_private(&pkey, DCRYPT_FORMAT_DOVECOT, "1\t716\t0\t048FD04FD3612B22D32790C592CF21CEF417EFD2EA34AE5F688FA5B51BED29E05A308B68DA78E16E90B47A11E133BD9A208A2894FD01B0BEE865CE339EA3FB17AC\td0cfaca5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd433615e77a0", NULL, NULL, &error));
	if (pkey != NULL) {
		buffer_set_used_size(key_1, 0);
		/* check that key_id matches */
		struct dcrypt_public_key *pubkey = NULL;
		dcrypt_key_convert_private_to_public(pkey, &pubkey);
		test_assert(dcrypt_key_store_public(pubkey, DCRYPT_FORMAT_DOVECOT, key_1, NULL));
		buffer_set_used_size(key_1, 0);
		dcrypt_key_id_public(pubkey, "sha256", key_1, &error);
		test_assert(strcmp("792caad4d38c9eb2134a0cbc844eae386116de096a0ccafc98479825fc99b6a1", binary_to_hex(key_1->data, key_1->used)) == 0);

		dcrypt_key_free_public(&pubkey);
		pkey2 = NULL;

		test_assert(dcrypt_key_load_private(&pkey2, DCRYPT_FORMAT_DOVECOT, "1\t716\t1\t0567e6bf9579813ae967314423b0fceb14bda24749303923de9a9bb9370e0026f995901a57e63113eeb2baf0c940e978d00686cbb52bd5014bc318563375876255\t0300E46DA2125427BE968EB3B649910CDC4C405E5FFDE18D433A97CABFEE28CEEFAE9EE356C792004FFB80981D67E741B8CC036A34235A8D2E1F98D1658CFC963D07EB\td0cfaca5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd433615e77a0\t7c9a1039ea2e4fed73e81dd3ffc3fa22ea4a28352939adde7bf8ea858b00fa4f", NULL, pkey, &error));
		if (pkey2 != NULL) {
			buffer_set_used_size(key_1, 0);
			/* check that key_id matches */
			struct dcrypt_public_key *pubkey = NULL;
			dcrypt_key_convert_private_to_public(pkey2, &pubkey);
			test_assert(dcrypt_key_store_public(pubkey, DCRYPT_FORMAT_DOVECOT, key_1, NULL));
			buffer_set_used_size(key_1, 0);
			test_assert(dcrypt_key_id_public_old(pubkey, key_1, &error));
			test_assert(strcmp("7c9a1039ea2e4fed73e81dd3ffc3fa22ea4a28352939adde7bf8ea858b00fa4f", binary_to_hex(key_1->data, key_1->used)) == 0);

			dcrypt_key_free_public(&pubkey);
			dcrypt_key_free_private(&pkey2);
		}
		dcrypt_key_free_private(&pkey);
	}

	test_end();
}

static
void test_load_v1_public_key(void)
{
	test_begin("test_load_v1_public_key");

	const char* data1 = "1\t716\t030131D8A5FD5167947A0AE9CB112ADED6526654635AA5887051EE2364414B60FF32EBA8FA0BBE9485DBDE8794BBBCB44BBFC0D662A4287A848BA570D4E5E45A11FE0F\td0cfaca5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd433615e77a0";

	const char* error = NULL;
	const char* key_hash = NULL;
	const char* encryption_key_hash = NULL;

	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type encryption_type;

	bool ret = dcrypt_key_string_get_info(data1, &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);

	test_assert(ret == TRUE);
	test_assert(error == NULL);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_1);
	test_assert(kind == DCRYPT_KEY_KIND_PUBLIC);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(key_hash != NULL && strcmp(key_hash, "d0cfaca5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd433615e77a0") == 0);
	test_assert(encryption_key_hash == NULL);

	struct dcrypt_public_key *pub_key = NULL;
	ret = dcrypt_key_load_public(&pub_key, format, data1, &error);
	test_assert(ret == TRUE);
	test_assert(error == NULL);

	test_assert(dcrypt_key_type_public(pub_key) == DCRYPT_KEY_EC);

	dcrypt_key_free_public(&pub_key);
	test_assert(pub_key == NULL);

	test_end();
}

static
void test_load_v2_key(void)
{
	const char *keys[] = {
		"-----BEGIN PRIVATE KEY-----\n" \
"MGcCAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcETTBLAgEBBCC25AkD65uhlZXCAdwN\n" \
"yLJV2ui8A/CUyqyEMrezvwgMO6EkAyIAAybRUR3MsH0+0PQcDwkrXOJ9aePwzTQV\n" \
"DN51+n1JCxbI\n" \
"-----END PRIVATE KEY-----\n",
		"2\t1.2.840.10045.3.1.7\t0\t0000002100b6e40903eb9ba19595c201dc0dc8b255dae8bc03f094caac8432b7b3bf080c3b\tab13d251976dedab546b67354e7678821740dd534b749c2857f66bf62bbaddfd",
		"2\t1.2.840.10045.3.1.7\t2\taes-256-ctr\t2b19763d4bbf7754\tsha256\t2048\tc36fa194669a1aec400eae32fbadaa7c58b14f53c464cfbb0a4b61fbe24ab7750637c4025d\tab13d251976dedab546b67354e7678821740dd534b749c2857f66bf62bbaddfd",
		"2\t1.2.840.10045.3.1.7\t1\taes-256-ctr\t7c7f1d12a7c011de\tsha256\t2048\tf5d1de11d58a81b141cf038012a618623e9d7b18062deeb3a4e35872c62ca0837db8688370\t021abfbc5bc4f6cf49c40b9fc388c4616ea079941675f477ee4557df1919626d35\tab13d251976dedab546b67354e7678821740dd534b749c2857f66bf62bbaddfd\tab13d251976dedab546b67354e7678821740dd534b749c2857f66bf62bbaddfd"
	};

	test_begin("test_load_v2_key");
	const char *error = NULL;
	buffer_t *tmp = buffer_create_dynamic(default_pool, 256);

	struct dcrypt_private_key *priv,*priv2;

	test_assert_idx(dcrypt_key_load_private(&priv2, DCRYPT_FORMAT_PEM, keys[0], NULL, NULL, &error), 0);
	test_assert_idx(dcrypt_key_store_private(priv2, DCRYPT_FORMAT_PEM, NULL, tmp, NULL, NULL, &error), 0);
	test_assert_idx(strcmp(str_c(tmp), keys[0])==0, 0);
	buffer_set_used_size(tmp, 0);

	test_assert_idx(dcrypt_key_load_private(&priv, DCRYPT_FORMAT_DOVECOT, keys[1], NULL, NULL, &error), 1);
	test_assert_idx(dcrypt_key_store_private(priv, DCRYPT_FORMAT_DOVECOT, NULL, tmp, NULL, NULL, &error), 1);
	test_assert_idx(strcmp(str_c(tmp), keys[1])==0, 1);
	buffer_set_used_size(tmp, 0);
	dcrypt_key_free_private(&priv);

	test_assert_idx(dcrypt_key_load_private(&priv, DCRYPT_FORMAT_DOVECOT, keys[2], "This Is Sparta", NULL, &error), 2);
	test_assert_idx(dcrypt_key_store_private(priv, DCRYPT_FORMAT_DOVECOT, "aes-256-ctr", tmp, "This Is Sparta", NULL, &error), 2);
	buffer_set_used_size(tmp, 0);
	dcrypt_key_free_private(&priv);

	struct dcrypt_public_key *pub = NULL;
	dcrypt_key_convert_private_to_public(priv2, &pub);
	test_assert_idx(dcrypt_key_load_private(&priv, DCRYPT_FORMAT_DOVECOT, keys[3], NULL, priv2, &error), 3);
	test_assert_idx(dcrypt_key_store_private(priv, DCRYPT_FORMAT_DOVECOT, "ecdh-aes-256-ctr", tmp, NULL, pub, &error), 3);
	buffer_set_used_size(tmp, 0);
	dcrypt_key_free_private(&priv2);
	dcrypt_key_free_private(&priv);
	dcrypt_key_free_public(&pub);

	buffer_free(&tmp);

	if (error != NULL) error = NULL;

	test_end();
}

static
void test_load_v2_public_key(void)
{
	struct dcrypt_public_key *pub = NULL;
	const char *error;

	test_begin("test_load_v2_public_key");
	const char *key = "2\t3058301006072a8648ce3d020106052b810400230344000301c50954e734dd8b410a607764a7057065a45510da52f2c6e28e0cb353b9c389fa8cb786943ae991fce9befed78fb162fbbc615415f06af06c8cc80c37f4e94ff6c7\t185a7212542782e239111f9c19d126ad55b18ddaf4883d66afe8d9627c3607d8";

	test_assert(dcrypt_key_load_public(&pub, DCRYPT_FORMAT_DOVECOT, key, &error));

	buffer_t *tmp = buffer_create_dynamic(default_pool, 256);

	if (pub != NULL) {
		test_assert(dcrypt_key_store_public(pub, DCRYPT_FORMAT_DOVECOT, tmp, &error));
		test_assert(strcmp(key, str_c(tmp))==0);
		buffer_free(&tmp);
		dcrypt_key_free_public(&pub);
	}

	test_end();
}

static
void test_get_info_v2_key(void) {
	test_begin("test_get_info_v2_key");

	const char *key = "2\t305e301006072a8648ce3d020106052b81040026034a000203fcc90034fa03d6fb79a0fc8b3b43c3398f68e76029307360cdcb9e27bb7e84b3c19dfb7244763bc4d442d216f09b7b7945ed9d182f3156550e9ee30b237a0217dbf79d28975f31\t86706b69d1f640011a65d26a42f2ba20a619173644e1cc7475eb1d90966e84dc";
	enum dcrypt_key_format format;
	enum dcrypt_key_version version = DCRYPT_KEY_VERSION_NA;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type encryption_type;
	const char *encryption_key_hash = NULL;
	const char *key_hash = NULL;
	const char *error = NULL;

	test_assert(dcrypt_key_string_get_info(key, &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error));
	test_assert(error == NULL);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_2);

	test_assert(kind == DCRYPT_KEY_KIND_PUBLIC);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(encryption_key_hash == NULL);
	test_assert(key_hash != NULL && strcmp(key_hash,
		"86706b69d1f640011a65d26a42f2ba20a619173644e1cc7475eb1d90966e84dc") == 0);

	test_end();
}

static
void test_gen_and_get_info_rsa_pem(void)
{
	test_begin("test_gen_and_get_info_rsa_pem");

	const char *error = NULL;
	bool ret = FALSE;
	struct dcrypt_keypair pair;
	string_t* buf = str_new(default_pool, 4096);

	ret = dcrypt_keypair_generate(&pair, DCRYPT_KEY_RSA, 1024, NULL, NULL);
	test_assert(ret == TRUE);

	/* test public key */
	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type encryption_type;
	const char *encryption_key_hash;
	const char *key_hash;

	ret = dcrypt_key_store_public(pair.pub, DCRYPT_FORMAT_PEM, buf,
			&error);
	test_assert(ret == TRUE);

	ret = dcrypt_key_string_get_info(str_c(buf), &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);
	test_assert(ret == TRUE);
	test_assert(format == DCRYPT_FORMAT_PEM);
	test_assert(version == DCRYPT_KEY_VERSION_NA);

	test_assert(kind == DCRYPT_KEY_KIND_PUBLIC);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(encryption_key_hash == NULL);
	test_assert(key_hash == NULL);

	/* test private key */
	buffer_set_used_size(buf, 0);
	ret = dcrypt_key_store_private(pair.priv, DCRYPT_FORMAT_PEM, NULL,
			buf, NULL, NULL, &error);

	test_assert(ret == TRUE);

	ret = dcrypt_key_string_get_info(str_c(buf), &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);

	test_assert(ret == TRUE);
	test_assert(format == DCRYPT_FORMAT_PEM);
	test_assert(version == DCRYPT_KEY_VERSION_NA);

	test_assert(kind == DCRYPT_KEY_KIND_PRIVATE);

	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(encryption_key_hash == NULL);
	test_assert(key_hash == NULL);

	dcrypt_keypair_free(&pair);
	buffer_free(&buf);

	test_end();
}

int main(void) {
	random_init();
	dcrypt_initialize("openssl", NULL, NULL);

	static void (*test_functions[])(void) = {
		test_cipher_test_vectors,
		test_cipher_aead_test_vectors,
		test_hmac_test_vectors,
		test_load_v1_keys,
		test_load_v1_key,
		test_load_v1_public_key,
		test_load_v2_key,
		test_load_v2_public_key,
		test_get_info_v2_key,
		test_gen_and_get_info_rsa_pem,
		NULL
	};

	int ret = test_run(test_functions);

	dcrypt_deinitialize();
	random_deinit();

	return ret;
}
