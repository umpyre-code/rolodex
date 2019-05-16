CREATE TYPE account_action AS ENUM ( 'created',
  'deleted',
  'updated',
  'password updated',
  'public key updated',
  'phone number updated',
  'email updated',
  'authenticated')
