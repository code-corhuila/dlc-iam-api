INSERT INTO iam.users
  (user_id, email, display_name, password_hash, status, email_verified_at,
   created_at, updated_at)
VALUES
  ('00000000-0000-0000-0000-000000000501', 'lock-test@example.test',
   'Synthetic Dentist',
   '$2a$12$Lbh5YjIxqA2/VzposOIrfu8W2ByjWvqxQIIlf9DaHfvfNgstcX7QG',
   'ACTIVE', now(), now(), now());
INSERT INTO iam.user_roles (user_id, role, assigned_at)
VALUES ('00000000-0000-0000-0000-000000000501', 'DENTIST', now());
