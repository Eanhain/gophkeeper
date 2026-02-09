ALTER TABLE user_credentials DROP CONSTRAINT IF EXISTS uq_credentials_user_login;
ALTER TABLE user_text_items DROP CONSTRAINT IF EXISTS uq_text_user_title;
ALTER TABLE user_binary_items DROP CONSTRAINT IF EXISTS uq_binary_user_filename;
ALTER TABLE user_cards DROP CONSTRAINT IF EXISTS uq_cards_user_cardholder;
