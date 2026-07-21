-- Minimal push_notification lua driver for the bundle PoC.
-- Exercises the mail_lua + push_notification_lua dlopen path on LMTP delivery.
-- Callback names are fixed by the plugin (push-notification-driver-lua.c).

function dovecot_lua_notify_begin_txn(user)
  return { username = user.username, events = 0 }
end

function dovecot_lua_notify_event_message_new(ctx, event)
  ctx.events = ctx.events + 1
end

function dovecot_lua_notify_end_txn(ctx)
  -- A real driver would emit a notification here; the PoC just needs the
  -- transaction to complete without error.
end
