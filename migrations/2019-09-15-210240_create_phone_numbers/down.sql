ALTER TABLE clients ADD CONSTRAINT clients_phone_number_key UNIQUE (phone_number);

DROP TABLE phone_numbers;
