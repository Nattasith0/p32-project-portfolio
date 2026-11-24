# ผลตรวจชุดพื้นฐานและบัญชี

ตรวจวันที่ **24 พฤศจิกายน 2569** จากชุดไฟล์ที่จะเผยแพร่นี้โดยตรง
สภาพแวดล้อม Windows, Node.js 22.23.4, npm 10.9.9, PostgreSQL 18.6 และ Google Chrome แบบ headless

| รายการ | ผลตรวจ |
| --- | --- |
| Backend: npm test | ผ่าน 497 รายการ ไม่ข้ามรายการ |
| Frontend: npm test | ผ่าน 46 รายการ ไม่ข้ามรายการ |
| Frontend: lint | ผ่าน |
| Frontend: TypeScript | ผ่าน |
| Frontend: production build | ผ่าน หน้า / และ /admin/roles |
| PostgreSQL และ browser acceptance | ผ่าน 24 ข้อ รวมรายการด้านล่าง |

ชุด npm test รวม **543 รายการ** มีทั้งการตรวจฟังก์ชัน บริการ และพฤติกรรม API
หลายรายการใช้ dependency จำลอง จึงแยกจากการตรวจฐานข้อมูลจริงและเบราว์เซอร์ด้านล่าง
ยังไม่ได้ตั้ง CI ให้รันอัตโนมัติเมื่อ push

## การตรวจฐานข้อมูลและหน้าจอจริง

สร้าง PostgreSQL cluster ชั่วคราวและบัญชี p32_app/p32_migrator ที่ไม่เป็น superuser
ใช้พอร์ตแยกจากระบบพัฒนา รหัสผ่านและกุญแจสุ่มเฉพาะรอบตรวจ ใช้บัญชีสมมติสองบัญชี
เปิด Backend พร้อม Frontend ที่ production build แล้วและตรวจผ่าน Chrome

1. ฐานเปล่าลง migrations ได้ 6 รายการ; รันซ้ำได้ 0 รายการ
2. Seed ผ่านการตรวจเงื่อนไขและสร้าง admin_demo/student_demo
3. Session repository ผ่านกับ PostgreSQL จริง และข้อมูลทดสอบของสคริปต์ถูก rollback
4. หน้า Login เปิดได้; รหัสผ่านผิดแสดงข้อความผิดพลาด
5. ผู้ไม่เข้าสู่ระบบเข้าถึง API จัดการบทบาทไม่ได้ (401) และหน้าจอแนะนำให้เข้าสู่ระบบ
6. Login จาก Origin ภายนอกถูกปฏิเสธ (403)
7. นักศึกษา Login ได้และ session อยู่หลัง reload
8. นักศึกษาเข้า API จัดการบทบาทไม่ได้ (403) และหน้าจออธิบายสิทธิ์
9. ผู้ดูแล Login ได้; session cookie เป็น HttpOnly และ SameSite=Lax ตามค่าตั้งของระบบ
10. ผู้ดูแลดูรายการบทบาท ค้นหานักศึกษา และเปิดรายละเอียดบทบาทได้
11. มอบหมายและถอน advisor ผ่านหน้าจอยืนยันได้; ฐานข้อมูลบันทึกประวัติ 2 รายการ
12. Logout ที่ไม่มี CSRF ถูกต้องถูกปฏิเสธ; Logout ผ่านหน้าจอเพิกถอน session และกลับหน้า Login
13. หน้า Login ขนาด 390 x 844 ไม่เกิด horizontal overflow
14. ไม่พบ uncaught JavaScript errors ระหว่างเส้นทางที่ตรวจ

รายการข้างต้นรวมผลย่อย 24 assertions ไม่ได้หมายถึงทุกหน้าจอของระบบเต็ม
ตัวช่วยตรวจฐานข้อมูล/Chrome ใช้เฉพาะพื้นที่ทดสอบในเครื่องและไม่ได้รวมเป็น npm test ของ repository

## รันการตรวจที่มาพร้อม repository

เริ่มจากโฟลเดอร์ราก หลังติดตั้งตาม [คู่มือติดตั้ง](foundation-setup.md):

```powershell
npm.cmd --prefix backend test
npm.cmd --prefix frontend test
npm.cmd --prefix frontend run lint
npm.cmd --prefix frontend run typecheck
npm.cmd --prefix frontend run build
```

หลังตั้งค่าฐานพัฒนาสำหรับชุดนี้แล้ว สามารถตรวจ session repository เพิ่มได้:

```powershell
npm.cmd --prefix backend run db:check:sessions
```

เปิดระบบและตรวจ Login, Logout, reload และ /admin/roles ด้วยบัญชีทั้งสองตามรายการด้านบน
รหัสผ่านใช้ค่าที่ตั้งเองใน backend/.env.seed ไม่ได้ฝังไว้ในโค้ด

## ขอบเขตผลตรวจ

ผลนี้รองรับชุดพื้นฐานและบัญชีที่เผยแพร่เท่านั้น ไม่ใช่การตรวจรับระบบเต็ม
ยังไม่ได้ตรวจการเชื่อมต่อกับคู่ทีมจริง Login กลาง หรือการใช้งาน production
การยืนยันอีเมลใน seed เป็นข้อมูลสมมติ ไม่ได้ส่งอีเมลจริง
การทดสอบจอเล็กใช้ Chrome จำลองขนาดหน้าจอ ไม่ใช่การทดลองบนโทรศัพท์จริง

[กลับภาพรวม](../README.md)
