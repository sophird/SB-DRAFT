insert into public.profiles (email, full_name, role)
values
  ('admin@serbisyoburgos.com', 'Admin Burgos', 'admin')
on conflict (email) do update
set
  full_name = excluded.full_name,
  role = excluded.role;
