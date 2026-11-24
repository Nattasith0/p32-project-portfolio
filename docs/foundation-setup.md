# ติดตั้งชุดพื้นฐานและบัญชีบนเครื่องพัฒนา

คำสั่งใช้ PowerShell โดยเริ่มจากโฟลเดอร์รากของ repository
ใช้ PostgreSQL สำหรับพัฒนาแยกจากข้อมูลจริงและสร้างบัญชีฐานข้อมูลสองบัญชีด้วยรหัสผ่านต่างกัน

## 1. เตรียมฐานข้อมูลใหม่

เปิด psql ด้วยบัญชีผู้ดูแล PostgreSQL แล้วรัน:
```sql
CREATE ROLE p32_migrator
WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE p32_app
WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
```

ตั้งรหัสผ่านผ่านช่องรับรหัสผ่านของ psql:
```text
\password p32_migrator
\password p32_app
```

สร้างฐานนอก transaction:
```sql
CREATE DATABASE p32_dev
WITH OWNER = p32_migrator ENCODING = 'UTF8' TEMPLATE = template0;
REVOKE ALL ON DATABASE p32_dev FROM PUBLIC;
GRANT CONNECT ON DATABASE p32_dev TO p32_app;
```

หากมีฐานหรือบัญชีอยู่แล้ว ให้ตรวจสภาพแวดล้อมเดิมก่อน ไม่ต้องสร้างซ้ำ

## 2. ติดตั้ง dependencies และค่าตั้ง
```powershell
npm.cmd ci --prefix backend --ignore-scripts
npm.cmd ci --prefix frontend

foreach ($p32EnvFile in @('.env', '.env.migrations', '.env.seed')) {
    $p32Target = Join-Path 'backend' $p32EnvFile
    if (-not (Test-Path -LiteralPath $p32Target)) {
        Copy-Item -LiteralPath ($p32Target + '.example') -Destination $p32Target
    }
}
```

ตั้งค่าไฟล์บนเครื่องดังนี้:

| ไฟล์ | ค่าที่ต้องตั้ง |
| --- | --- |
| backend/.env | PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD ของ p32_app, NODE_ENV=development และ P32_WEB_ORIGIN=http://localhost:5173 |
| backend/.env.migrations | ค่าฐาน p32_dev ของ p32_migrator |
| backend/.env.seed | P32_ALLOW_DEV_SEED=true และรหัสผ่าน P32_SEED_ADMIN_PASSWORD / P32_SEED_STUDENT_PASSWORD ที่ต่างกัน ยาว 15–1024 Unicode code points |

สร้างกุญแจ JWT และ CSRF คนละค่า แล้วใส่ใน P32_JWT_SECRET_HEX และ P32_CSRF_SECRET_HEX ของ backend/.env:
```powershell
node -e "const c=require('node:crypto'); for(let i=0;i<2;i++) console.log(c.randomBytes(32).toString('hex'))"
```

ไฟล์ค่าตั้งจริงเก็บเฉพาะเครื่อง ไม่ commit ขึ้น Git

## 3. ลง migrations และ seed
```powershell
npm.cmd --prefix backend run db:check
npm.cmd --prefix backend run db:migrate:check
npm.cmd --prefix backend run db:migrate:up
npm.cmd --prefix backend run db:seed:check
npm.cmd --prefix backend run db:seed
```

Seed อนุญาตเฉพาะฐาน p32_dev บน loopback ในโหมด development ผ่านบัญชี p32_migrator ที่ไม่เป็น superuser
บัญชีที่ได้คือ admin_demo และ student_demo โดยใช้รหัสผ่านที่ตั้งเอง

## 4. เปิด Backend และ Frontend

หน้าต่างแรก:
```powershell
npm.cmd --prefix backend run dev
```

หน้าต่างที่สอง:
```powershell
npm.cmd --prefix frontend run dev
```

เปิด http://localhost:5173/ แล้วลอง Login/Logout
ผู้ดูแลเปิด http://localhost:5173/admin/roles เพื่อดูรายการบทบาท ค้นหาบัญชี และจัดการบทบาทได้ตามสิทธิ์
บัญชีนักศึกษาไม่สามารถเรียก API จัดการบทบาทได้

Frontend ส่ง /api/* ไป http://127.0.0.1:3001 เป็นค่าเริ่มต้น
หากเปลี่ยน P32_API_ORIGIN ให้ตั้งก่อน build และ build ใหม่

สำหรับทดลอง Frontend ที่ build แล้ว ให้หยุด Frontend dev server ก่อน:
```powershell
npm.cmd --prefix frontend run build
npm.cmd --prefix frontend start
```

หากพอร์ต 5173 หรือ 3001 ถูกใช้อยู่ ให้ตรวจโปรแกรมที่เปิดไว้ก่อนเริ่มอีกชุด

[กลับภาพรวม](../README.md)
