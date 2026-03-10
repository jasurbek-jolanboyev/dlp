import os
import re
import asyncio
import logging
from datetime import datetime
from PIL import Image
# Ma'lumotlar bazasi
import database as db

# Asosiy kutubxonalar
import vt
import PyPDF2
import google.generativeai as genai
from docx import Document
from openpyxl import load_workbook
from dotenv import load_dotenv

# Pyrogram
from pyrogram import Client, filters
from pyrogram.types import (Message, InlineKeyboardMarkup, InlineKeyboardButton, 
                            CallbackQuery, ReplyKeyboardMarkup, KeyboardButton, 
                            ReplyKeyboardRemove)

# --- 0. KONFIGURATSIYA VA LIMITLAR ---
SCAN_CACHE = {}

fast_scan_limiter = asyncio.Semaphore(5)

heavy_file_limiter = asyncio.Semaphore(2)

# --- 1. SOZLAMALAR VA LOGGING ---
load_dotenv()
db.init_db()
logging.basicConfig(level=logging.INFO)

# --- OCR YUKLANISHI ---
OCR_AVAILABLE = False
reader = None
try:
    import easyocr
    # MacBook i9 da GPU yo'qligi sababli gpu=False
    reader = easyocr.Reader(['uz', 'en'], gpu=False)
    OCR_AVAILABLE = True
    logging.info("✅ EasyOCR muvaffaqiyatli yuklandi.")
except Exception as e:
    logging.warning(f"⚠️ OCR yuklanmadi. Faqat Gemini Vision ishlaydi: {e}")

try:
    API_ID = int(os.getenv("API_ID"))
    API_HASH = os.getenv("API_HASH")
    BOT_TOKEN = os.getenv("BOT_TOKEN")
    SUPER_ADMIN = int(os.getenv("SUPER_ADMIN_ID", "0"))
    DATABASE_CHANNEL = -1003725225836
    # DATABASE_CHANNEL = int(os.getenv("DATABASE_CHANNEL", "0"))
    VT_API_KEY = os.getenv("VT_API_KEY")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
except Exception as e:
    exit(f"❌ .env sozlamalarida xatolik: {e}")

genai.configure(api_key=GEMINI_API_KEY)
ai_model = genai.GenerativeModel('gemini-1.5-flash')

app = Client("DLP_AI", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# --- 2. XAVFSIZLIK FILTRLARI ---
uzb_series = r"(?:AA|AB|AC|AD|AE|FA|KA|RR|UZ|TT|AF|BA)"
PATTERNS = {
    '💳 Bank Kartasi': r'(?:8600|9860|4444|5100|5300|6262|5445|5555)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4,8}',
    '🛂 Passport/ID': rf'{uzb_series}[\s-]?\d{{7}}', 
    '🆔 JSHSHIR': r'[3-6]\d{13}', 
    '🚗 Prava/Tex-pasport': r'\d{2}[\s-]?[A-Z]{2}[\s-]?\d{6}'
}

# --- 3. SCANNER FUNKSIYALARI ---

async def check_malicious_ai(text: str):
    """Matnni Gemini AI orqali DLP (Data Loss Prevention) tahlil qilish"""
    if not GEMINI_API_KEY or len(text) < 10: 
        return False
    try:
        prompt = (
                "Siz kiberxavfsizlik mutaxassisiz. Ushbu rasmda quyidagilarni qidiring: "
                "1. O'zbekiston yoki boshqa davlat passporti (Seriya va raqam). "
                "2. Bank kartasi (16 talik raqam). "
                "3. JSHSHIR (14 talik raqam). "
                "4. Shaxsiy guvohnomalar. "
                "Agar birortasini topsangiz, faqat topilgan narsa nomini yozing (masalan: 'Passport'). "
                "Agar rasmda faqat manzara, chat yoki xavfsiz narsa bo'lsa, faqat 'SAFE' deb javob bering."
            )
        # Gemini javobini executor'da kutamiz (blocking bo'lmasligi uchun)
        response = await asyncio.to_thread(ai_model.generate_content, prompt)
        return "DANGER" in response.text.upper()
    except Exception as e:
        logging.error(f"Gemini Text Scan Error: {e}")
        return False

async def check_image_ai(file_path: str):
    """Rasmni Gemini Vision orqali tahlil qilish (DLP uchun)"""
    if not GEMINI_API_KEY: 
        return None
    try:
        # Faylni Gemini serveriga yuklash (path= o'chirildi)
        img_file = await asyncio.to_thread(genai.upload_file, file_path)
        
        prompt = (
            "Ushbu rasmda quyidagilarni aniqlang: Passport, ID karta, "
            "bank kartasi raqamlari, JSHSHIR yoki talabalik guvohnomasi. "
            "Agar xavf topilsa, nomini ayting (masalan: 'Passport'). "
            "Agar mutlaqo xavfsiz bo'lsa, faqat 'SAFE' deb javob bering."
        )
        
        # Muhim: [img_file, prompt] tartibida yuboriladi
        response = await asyncio.to_thread(ai_model.generate_content, [img_file, prompt])
        
        # Faylni Gemini serveridan o'chirish
        await asyncio.to_thread(genai.delete_file, img_file.name)
        
        res_text = response.text.strip().upper()
        if "SAFE" in res_text:
            return None
        return res_text
    except Exception as e:
        logging.error(f"❌ Gemini Vision Xatosi: {e}")
        return None

async def vt_scan_file(file_path: str):
    if not VT_API_KEY: return False
    try:
        async with vt.Client(VT_API_KEY) as client:
            with open(file_path, "rb") as f:
                # Faylni yuklash
                analysis = await client.scan_file_async(f)
                
                # Kutish jarayoni (Deadline exceeded oldini olish uchun)
                for _ in range(15): # 75 soniyagacha kutadi
                    await asyncio.sleep(5)
                    # Analiz holatini yangilangan usulda tekshiramiz
                    result = await client.get_object_async(f"/analyses/{analysis.id}")
                    if result.status == "completed":
                        return result.stats.get('malicious', 0) > 0
    except Exception as e:
        logging.error(f"VirusTotal Scan Error: {e}")
    return False

def extract_text_from_file(file_path: str):
    """Hujjatlardan (PDF, DOCX, XLSX) matnni ajratib olish"""
    ext = os.path.splitext(file_path)[1].lower()
    text = ""
    try:
        if ext == '.pdf':
            pdf = PyPDF2.PdfReader(file_path)
            for page in pdf.pages:
                text += page.extract_text() or ""
        elif ext in ['.docx', '.doc']:
            doc = Document(file_path)
            text = "\n".join([p.text for p in doc.paragraphs])
        elif ext in ['.xlsx', '.xls']:
            wb = load_workbook(file_path, data_only=True)
            for sheet in wb.sheetnames:
                for row in wb[sheet].iter_rows(values_only=True):
                    text += " ".join([str(cell) for cell in row if cell]) + " "
    except Exception as e:
        logging.error(f"File Extraction Error ({ext}): {e}")
    return text

# --- 3. SCANNER FUNKSIYALARI (YANGILANGAN) ---

async def advanced_scan(message: Message):
    """Skanerlashda xavfsizlikni kuchaytirilgan varianti"""
    file_id = "none"
    if message.document: file_id = message.document.file_unique_id
    elif message.photo: file_id = message.photo.file_unique_id

    # 1. Matn va Caption tahlili (Regex + Gemini)
    content = f"{message.text or ''} {message.caption or ''}".strip()
    if content:
        clean_text = content.replace(" ", "").replace("-", "")
        for label, pattern in PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, clean_text):
                return label
        if await check_malicious_ai(content):
            return "⚠️ Shubhali mazmun (AI)"

    # 2. Hujjat va Fayl tahlili (VirusTotal - ENG MUHIMI)
    if message.document:
        if message.document.file_size <= 50 * 1024 * 1024: # 50MB limit
            file_name = message.document.file_name or "temp_file"
            path = await message.download(file_name=f"downloads/{file_id}_{file_name}")
            
            try:
                # VirusTotal tekshiruvi
                is_virus = await vt_scan_file(path) 
                if is_virus:
                    return "🦠 Virus/Zararli dastur (Malware)"
                
                # Hujjat ichidagi matnni tekshirish (DLP uchun)
                file_text = extract_text_from_file(path)
                if file_text:
                    clean_file_text = file_text.replace(" ", "").replace("-", "")
                    for label, pattern in PATTERNS.items():
                        if re.search(pattern, clean_file_text, re.IGNORECASE):
                            return f"{label} (Hujjat ichida)"
            except Exception as e:
                logging.error(f"Fayl skanerlashda xato: {e}")
            finally:
                if os.path.exists(path): os.remove(path)

    # 3. Rasm tahlili (OCR + AI Vision)
    if message.photo:
        img_path = await message.download(file_name=f"downloads/{file_id}.jpg")
        try:
            threat = None
            if OCR_AVAILABLE:
                results = await asyncio.to_thread(reader.readtext, img_path)
                detected_text = " ".join([res[1] for res in results]).upper().replace(" ", "")
                for label, pattern in PATTERNS.items():
                    if re.search(pattern, detected_text):
                        threat = f"{label} (OCR)"
                        break

            if not threat:
                threat_ai = await check_image_ai(img_path)
                if threat_ai: 
                    threat = f"{threat_ai} (AI Vision)"
            
            return threat
        finally:
            if os.path.exists(img_path): os.remove(img_path)
                        
    return None

    # 3. Fayl tahlili (APK va boshqalar)
    if message.document:
        # Katta fayllarni ham tekshirish uchun limitni 50MB ga chiqaramiz
        if message.document.file_size <= 50 * 1024 * 1024:
            path = await message.download()
            
            # VirusTotal (APKlar uchun eng muhimi)
            # Tahlil vaqtini 60 sekundga chiqaramiz
            is_virus = await vt_scan_file(path) 
            if is_virus:
                if os.path.exists(path): os.remove(path)
                return "🦠 Virus/Zararli dastur (Malware)"
            
            # Hujjat ichidagi matn
            file_text = extract_text_from_file(path)
            if os.path.exists(path): os.remove(path)
            
            if file_text:
                clean_file_text = file_text.replace(" ", "").replace("-", "")
                for label, pattern in PATTERNS.items():
                    if re.search(pattern, clean_file_text, re.IGNORECASE):
                        return f"{label} (Hujjat ichida)"
                        
    return None

# --- 4. INTERFEYS VA TUGMALAR ---

active_chats = {} 
user_states = {}

def get_main_menu(user_id):
    btns = [
        [KeyboardButton("🛡 Bot Imkoniyatlari")],
        [KeyboardButton("📊 Statistika"), KeyboardButton("👨‍💻 Admin bilan bog'lanish")]
    ]
    if user_id == SUPER_ADMIN:
        btns.append([KeyboardButton("⚙️ Admin Paneli")])
    return ReplyKeyboardMarkup(btns, resize_keyboard=True)

def get_admin_panel():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📊 Stats", callback_data="admin_stats"), 
         InlineKeyboardButton("🏢 Guruhlar", callback_data="admin_groups")],
        [InlineKeyboardButton("👥 Foydalanuvchilar (Full)", callback_data="admin_users_detailed")],
        [InlineKeyboardButton("📢 Broadcast", callback_data="admin_broadcast"), 
         InlineKeyboardButton("👤 Userga xabar", callback_data="admin_send_user")],
        [InlineKeyboardButton("🚫 Oxirgi Xavflar", callback_data="view_log_0")],
        [InlineKeyboardButton("❌ Chiqish", callback_data="admin_close")]
    ])

# --- 5. PRIVATE HANDLER (USER & ADMIN INTERFACE) ---

@app.on_message(filters.private, group=-1)
async def private_manager(client, message: Message):
    user_id = message.from_user.id
    text = message.text
    
    # --- FOYDALANUVCHI FAOLLIGINI YANGILASH ---
    # Bu qator endi funksiya ichida va xatolarsiz ishlaydi
    await asyncio.to_thread(db.update_last_seen, user_id)

    state_data = user_states.get(user_id, {})
    state = state_data.get("step")

    # 1. Admin bilan jonli suhbat (Active Chat) mantiqi
    if user_id in active_chats:
        if text == "❌ Suhbatni yakunlash":
            partner = active_chats.pop(user_id)
            active_chats.pop(partner, None)
            await message.reply("🔚 Suhbat yakunlandi.", reply_markup=get_main_menu(user_id))
            await client.send_message(partner, "🔚 Suhbat yakunlandi.", reply_markup=get_main_menu(partner))
            return
        
        # Xabarni sherigiga nusxalash
        try:
            await message.copy(active_chats[user_id])
        except Exception as e:
            logging.error(f"Suhbat uzatishda xato: {e}")
        return

    # 2. Admin uchun maxsus buyruqlar (Broadcast va Direct Message)
    if user_id == SUPER_ADMIN:
        # Global xabar tarqatish
        if state == "wait_broadcast_msg":
            if text == "❌ Bekor qilish":
                user_states.pop(user_id)
                await message.reply("Bekor qilindi.", reply_markup=get_main_menu(user_id))
                return
            
            users = db.get_all_users()
            count = 0
            msg_status = await message.reply("🔄 Tarqatish boshlandi...")
            
            for u in users:
                try:
                    await message.copy(u[0])
                    count += 1
                    await asyncio.sleep(0.05) # Flood wait oldini olish uchun
                except: continue
            
            user_states.pop(user_id)
            await msg_status.edit_text(f"✅ Xabar {count} ta foydalanuvchiga yuborildi.")
            return

        # User ID sini kutish
        elif state == "wait_target_id":
            if text == "❌ Bekor qilish":
                user_states.pop(user_id)
                await message.reply("Bekor qilindi.", reply_markup=get_main_menu(user_id))
                return
            
            if text and text.isdigit():
                user_states[user_id] = {"step": "wait_direct_msg", "target_id": int(text)}
                await message.reply(f"👤 User `{text}` ga yuboriladigan xabarni kiriting (matn, rasm yoki video):")
            else:
                await message.reply("❌ Xato! ID faqat raqamlardan iborat bo'lishi kerak.")
            return

        # Tanlangan ID ga xabar yuborish
        elif state == "wait_direct_msg":
            target_id = state_data.get("target_id")
            try:
                await message.copy(target_id)
                await message.reply(f"✅ Xabar {target_id} ga muvaffaqiyatli yuborildi.", reply_markup=get_main_menu(user_id))
            except Exception as e:
                await message.reply(f"❌ Xabar yuborilmadi. Xato: {e}")
            user_states.pop(user_id)
            return

    # 3. Ro'yxatdan o'tish va Umumiy menyu
    if text == "/start":
        user = db.get_user(user_id)
        if not user:
            user_states[user_id] = {"step": "wait_name"}
            await message.reply("👋 Xush kelibsiz! DLP tizimidan foydalanish uchun ismingizni kiriting:", reply_markup=ReplyKeyboardRemove())
        else:
            await message.reply("🛡 DLP AI tizimi himoyaga tayyor!", reply_markup=get_main_menu(user_id))
        return

    # Ismni saqlash
    if state == "wait_name":
        if text and len(text) > 2:
            user_states[user_id] = {"step": "wait_phone", "name": text}
            await message.reply("📞 Telefon raqamingizni yuboring:", 
                                reply_markup=ReplyKeyboardMarkup([[KeyboardButton("📞 Kontaktni ulashish", request_contact=True)]], resize_keyboard=True))
        else:
            await message.reply("❌ Iltimos, haqiqiy ismingizni kiriting:")
        return

    # Kontakni saqlash va tugatish
    elif message.contact and state == "wait_phone":
        db.register_user(user_id, user_states[user_id]["name"], message.contact.phone_number)
        user_states.pop(user_id)
        await message.reply("✅ Ro'yxatdan o'tdingiz! Endi botdan to'liq foydalanishingiz mumkin.", reply_markup=get_main_menu(user_id))
        return

    # 4. Tugmalar mantiqi
    if text == "🛡 Bot Imkoniyatlari":
        info = ("🚀 **DLP Ultra AI nimalarga qodir?**\n\n"
                "1️⃣ **DLP Nazorati:** Guruhlarda maxfiy ma'lumotlarni aniqlaydi.\n"
                "2️⃣ **OCR Scan:** Rasmlar ichidagi matnlarni tahlil qiladi.\n"
                "3️⃣ **Fayl Analiz:** Hujjatlar ichidagi tahdidlarni topadi.\n"
                "4️⃣ **Antivirus:** Virusli fayllarni bloklaydi.\n"
                "5️⃣ **AI Himoya:** Gemini AI orqali aqlli tahlil.")
        await message.reply(info, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("➕ Guruhga qo'shish", url=f"https://t.me/{(await client.get_me()).username}?startgroup=new")]]))

    elif text == "📊 Statistika":
        u, g, t = db.get_stats()
        await message.reply(f"📊 **Hozirgi holat:**\n👤 Userlar: `{u}`\n🏢 Guruhlar: `{g}`\n🚫 Tahdidlar: `{t}`")

    elif text == "👨‍💻 Admin bilan bog'lanish":
        active_chats[user_id] = SUPER_ADMIN
        active_chats[SUPER_ADMIN] = user_id
        await message.reply("✍️ Xabaringizni yozing, admin tez orada javob beradi.", 
                            reply_markup=ReplyKeyboardMarkup([[KeyboardButton("❌ Suhbatni yakunlash")]], resize_keyboard=True))

    elif text == "⚙️ Admin Paneli" and user_id == SUPER_ADMIN:
        await message.reply("🛠 **Boshqaruv Paneli:**", reply_markup=get_admin_panel())

# --- 6. MONITORING HANDLER (To'liq Yangilangan va To'g'rilangan Versiya) ---

@app.on_message((filters.group | filters.channel) & ~filters.service, group=1)
async def monitor_handler(client, message: Message):
    """Barcha xabarlarni tutib qolish va tahlilga yo'naltirish"""
    
    # 1. Foydalanuvchi faolligini yangilash
    if message.from_user:
        asyncio.create_task(asyncio.to_thread(db.update_last_seen, message.from_user.id))

    chat_id = message.chat.id
    chat_title = message.chat.title or "Guruh/Kanal"
    db.add_group(chat_id, chat_title)
    
    user_id = message.from_user.id if message.from_user else 0
    user_info = f"{message.from_user.first_name} (@{message.from_user.username}) [ID:{user_id}]" if message.from_user else "Noma'lum"
    user_mention = message.from_user.mention if message.from_user else "Foydalanuvchi"

    # 2. Keshni tekshirish
    file_id = None
    if message.document: file_id = message.document.file_unique_id
    elif message.photo: file_id = message.photo.file_unique_id
    
    if file_id and file_id in SCAN_CACHE:
        threat = SCAN_CACHE[file_id]
        asyncio.create_task(smart_scan_processor(client, message, False, file_id, chat_id, chat_title, user_info, user_mention, manual_threat=threat))
        return

    # 3. Fayl turiga qarab yashirish mantiqi
    dangerous_exts = ('.apk', '.exe', '.bat', '.msi', '.py', '.js', '.scr', '.vbs', '.doc', '.docx', '.pdf', '.zip', '.rar')
    should_hide = False
    if message.document and message.document.file_name:
        if message.document.file_name.lower().endswith(dangerous_exts):
            should_hide = True

    # Skanerlashni fonda ishga tushirish
    asyncio.create_task(smart_scan_processor(client, message, should_hide, file_id, chat_id, chat_title, user_info, user_mention))

async def smart_scan_processor(client, message, should_hide, file_id, chat_id, chat_title, user_info, user_mention, manual_threat=None):
    """Xabarni tahlil qilish, jazolash va log kanalga yuborish"""
    threat = manual_threat 
    temp_msg = None
    user_id = message.from_user.id if message.from_user else 0

    # --- 1. TAHLIL BOSQICHI ---
    if threat is None:
        try:
            if should_hide:
                temp_msg = await message.reply(f"⏳ {user_mention}, kiber-tahlil ketmoqda...")
                await message.delete() 
                async with heavy_file_limiter:
                    threat = await advanced_scan(message)
            else:
                async with fast_scan_limiter:
                    threat = await advanced_scan(message)
            
            if file_id: SCAN_CACHE[file_id] = threat
        except Exception as e:
            logging.error(f"Skanerlash xatosi: {e}")

    # --- 2. JAZO VA OGOHLANTIRISH ---
    if threat:
        db.add_incident(chat_id, chat_title, user_info, threat, 
                        (message.text or message.caption or "Fayl/Rasm"), 
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        warn_text = f"🚨 {user_mention}, xavfli ma'lumot aniqlandi: `{threat}`. Bloklandi!"
        
        if temp_msg:
            await temp_msg.edit_text(warn_text)
            asyncio.create_task(delete_after_delay(temp_msg, 30))
        else:
            try:
                warn = await message.reply(warn_text)
                await message.delete()
                asyncio.create_task(delete_after_delay(warn, 30))
            except: pass
    else:
        if should_hide and temp_msg:
            try:
                await temp_msg.delete()
                await message.copy(chat_id) # Faylni qaytarish
            except: pass

    # --- 3. LOG KANALGA YUBORISH ---
    await log_to_private_channel(client, message, threat, chat_id, chat_title, user_info, user_id)

async def log_to_private_channel(client, message, threat, chat_id, chat_title, user_info, user_id):
    """Kanalga kiber-tahlil hisobotini yuborish (Peer ID muammosi yechilgan)"""
    if not DATABASE_CHANNEL: return
    
    try:
        # Peer ID xatosini oldini olish uchun integerga o'tkazamiz
        target_chat = int(DATABASE_CHANNEL)
        
        rank = "Foydalanuvchi"
        try:
            member = await client.get_chat_member(chat_id, user_id)
            if member.status.name == "OWNER": rank = "👑 Owner"
            elif member.status.name == "ADMINISTRATOR": rank = "👮 Admin"
        except: pass

        incident_count = db.get_user_history(user_id)
        status = "🚨 **BLOKLANDI**" if threat else "✅ **TOZA**"
        color = "🔴" if threat else "🟢"
        
        log_report = (
            f"{color} {status}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🏢 **Guruh:** `{chat_title}`\n"
            f"👤 **Foydalanuvchi:** {user_info}\n"
            f"🎖 **Mavqeyi:** `{rank}`\n"
            f"⚠️ **Xavf:** `{threat if threat else 'Hech qanday'}`\n"
            f"📊 **Incidentlar:** `{incident_count}-marta`\n"
            f"🕒 **Vaqt:** `{datetime.now().strftime('%H:%M:%S')}`\n"
            f"━━━━━━━━━━━━━━━━━━━━"
        )

        if message.photo or message.document or message.video:
            # Caption limitiga e'tibor beramiz
            await message.copy(target_chat, caption=log_report[:1024])
        else:
            msg_text = message.text or message.caption or "[Matn yo'q]"
            await client.send_message(target_chat, f"{log_report}\n\n📝 **Kontent:**\n`{msg_text}`")
            
    except Exception as e:
        logging.error(f"❌ Kanalga loglashda xato: {e}")

async def advanced_scan(message: Message):
    """Skanerlashda fayl yo'llarini to'g'ri boshqarish"""
    file_id = message.document.file_unique_id if message.document else (message.photo.file_unique_id if message.photo else "none")

    # 1. Matn/Caption tahlili
    content = f"{message.text or ''} {message.caption or ''}".strip()
    if content:
        clean_text = content.replace(" ", "").replace("-", "")
        for label, pattern in PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, clean_text):
                return label
        if await check_malicious_ai(content):
            return "⚠️ Shubhali mazmun (AI)"

    # 2. Rasm tahlili
    if message.photo:
        img_path = await message.download(file_name=f"downloads/{file_id}.jpg")
        threat = None
        
        if OCR_AVAILABLE:
            try:
                results = await asyncio.to_thread(reader.readtext, img_path)
                detected_text = " ".join([res[1] for res in results]).upper().replace(" ", "")
                for label, pattern in PATTERNS.items():
                    if re.search(pattern, detected_text):
                        threat = f"{label} (OCR)"
                        break
            except Exception as e:
                logging.error(f"OCR Error: {e}")

        if not threat:
            threat_ai = await check_image_ai(img_path)
            if threat_ai: threat = f"{threat_ai} (AI Vision)"

        if os.path.exists(img_path): os.remove(img_path)
        return threat

    # 3. Hujjat tahlili
    if message.document:
        if message.document.file_size <= 50 * 1024 * 1024:
            file_name = message.document.file_name or "temp_file"
            path = await message.download(file_name=f"downloads/{file_id}_{file_name}")
            
            try:
                is_virus = await vt_scan_file(path) 
                if is_virus: return "🦠 Virus/Zararli dastur"
                
                file_text = extract_text_from_file(path)
                if file_text:
                    clean_file_text = file_text.replace(" ", "").replace("-", "")
                    for label, pattern in PATTERNS.items():
                        if re.search(pattern, clean_file_text, re.IGNORECASE):
                            return f"{label} (Hujjat ichida)"
            finally:
                if os.path.exists(path): os.remove(path)
                        
    return None

async def delete_after_delay(msg: Message, delay: int):
    await asyncio.sleep(delay)
    try: await msg.delete()
    except: pass

# --- 7. CALLBACK HANDLER (To'liq va To'g'rilangan Versiya) ---
@app.on_callback_query()
async def admin_callback_handler(client, cb: CallbackQuery):
    data = cb.data
    user_id = cb.from_user.id

    # Faqat SUPER_ADMIN kira olishini tekshirish
    if user_id != SUPER_ADMIN:
        return await cb.answer("Siz admin emassiz!", show_alert=True)

    try:
        # 1. Statistika ko'rinishi
        if data == "admin_stats":
            u, g, t = db.get_stats()
            text = (f"📊 **Tizim statistikasi:**\n\n"
                    f"👤 Foydalanuvchilar: `{u}`\n"
                    f"🏢 Himoyadagi guruhlar: `{g}`\n"
                    f"🚫 Aniqlangan tahdidlar: `{t}`")
            await cb.message.edit_text(text, reply_markup=get_admin_panel())

        # 2. Guruhlar ro'yxati
        elif data == "admin_groups":
            groups = db.get_all_groups()
            text = "🏢 **Himoyadagi guruhlar ro'yxati:**\n\n"
            if not groups:
                text += "Hozircha guruhlar yo'q."
            else:
                for g in groups[:20]:
                    text += f"• {g[1]} (ID: `{g[0]}`)\n"
            await cb.message.edit_text(text, reply_markup=get_admin_panel())

        # 3. Foydalanuvchilar haqida batafsil ma'lumot (YANGI)
        elif data == "admin_users_detailed":
            users = db.get_all_users_detailed()
            text = "👥 **Foydalanuvchilar haqida batafsil ma'lumot:**\n\n"
            
            if not users:
                text += "Foydalanuvchilar topilmadi."
            else:
                # Telegram xabar limiti (4096 belgi) sababli oxirgi 15 tasini chiqaramiz
                for u in users[:15]:
                    u_id, name, phone, reg_date, last_seen = u
                    # Username'ni olishga harakat qilamiz
                    try:
                        user_obj = await client.get_users(u_id)
                        username = f"@{user_obj.username}" if user_obj.username else "Mavjud emas"
                    except:
                        username = "Noma'lum"

                    text += (f"👤 **Foydalanuvchi:** {name}\n"
                            f"🆔 **ID:** `{u_id}`\n"
                            f"🌐 **Username:** {username}\n"
                            f"📞 **Tel:** `{phone}`\n"
                            f"📅 **Ro'yxatdan o'tdi:** {reg_date}\n"
                            f"🕒 **Oxirgi faollik:** {last_seen}\n"
                            f"━━━━━━━━━━━━━━━━━━━━\n")
            
            await cb.message.edit_text(text, reply_markup=get_admin_panel())

        # 4. Global tarqatish (Broadcast)
        elif data == "admin_broadcast":
            user_states[user_id] = {"step": "wait_broadcast_msg"}
            await cb.message.edit_text(
                "📢 **Global xabar matnini yuboring:**\n\n(Hamma userlarga yuboriladi)", 
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Bekor qilish", callback_data="admin_stats")]])
            )

        # 5. Maxsus foydalanuvchiga yuborish (ID orqali)
        elif data == "admin_send_user":
            user_states[user_id] = {"step": "wait_target_id"}
            await cb.message.edit_text(
                "👤 **Xabar yubormoqchi bo'lgan user ID sini kiriting:**", 
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Bekor qilish", callback_data="admin_stats")]])
            )

        # 6. Paneldan chiqish
        elif data == "admin_close":
            await cb.message.delete()

        # 7. Tahdidlar logini ko'rish (Pagination)
        elif data.startswith("view_log_"):
            index = int(data.split("_")[-1])
            log = db.get_log_by_offset(index)
            total = db.get_total_logs_count()

            if not log:
                return await cb.answer("Arxiv tugadi", show_alert=True)

            report = (
                f"📂 **ARXIV HODISASI #{log[0]}**\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"🏢 **Guruh:** `{log[2]}`\n"
                f"👤 **User:** `{log[3]}`\n"
                f"⚠️ **Xavf:** `{log[4]}`\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"📝 **Xabar:**\n`{log[5]}`\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"📍 `{index + 1}` / `{total}`"
            )

            btns = []
            nav_row = []
            if index > 0:
                nav_row.append(InlineKeyboardButton("🆕 Yangi", callback_data=f"view_log_{index-1}"))
            if index + 1 < total:
                nav_row.append(InlineKeyboardButton("Eski ➡️", callback_data=f"view_log_{index+1}"))
            
            if nav_row:
                btns.append(nav_row)
            btns.append([InlineKeyboardButton("⬅️ Panelga qaytish", callback_data="admin_stats")])

            await cb.message.edit_text(report, reply_markup=InlineKeyboardMarkup(btns))

    except Exception as e:
        if "MESSAGE_NOT_MODIFIED" in str(e):
            await cb.answer("Yangilandi")
        else:
            logging.error(f"Callback xatosi: {e}")
            await cb.answer("Xatolik yuz berdi", show_alert=True)
            
if __name__ == "__main__":
    print("🚀 DLP AI ishga tushdi...")
    app.run()