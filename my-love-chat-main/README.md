# 🚀 Z-SPACE: Real-time Messaging & Video Calling Platform

**Z-SPACE** သည် Node.js, Socket.io နှင့် WebRTC တို့ကို အသုံးပြု၍ တည်ဆောက်ထားသော ခေတ်မီ Real-time ဆက်သွယ်ရေး Application တစ်ခုဖြစ်သည်။ စာတိုပေးပို့ခြင်း (Chatting) သာမက Voice Messages ပေးပို့ခြင်းနှင့် အရည်အသွေးမြင့် Video/Voice Call များကို တိုက်ရိုက်ပြုလုပ်နိုင်ရန် ဖန်တီးထားပါသည်။

---

## ✨ အဓိက လုပ်ဆောင်ချက်များ (Key Features)

* **💬 Real-time Chatting:** Socket.io နည်းပညာကြောင့် စာတိုများ ပေးပို့ခြင်းနှင့် လက်ခံခြင်းကို စက္ကန့်ပိုင်းအတွင်း မြန်ဆန်စွာ လုပ်ဆောင်နိုင်သည်။
* **📞 Peer-to-Peer Video/Voice Calls:** WebRTC (Simple-Peer) ကို အသုံးပြုထားသဖြင့် Server ကို ဝန်မပိစေဘဲ တိုက်ရိုက် Call ပြောဆိုနိုင်သည်။
* **🎙 Voice Messaging:** အသံဖိုင်များကို Recording ပြုလုပ်၍ Cloudinary ပေါ်သို့ တင်ကာ အလွယ်တကူ ပေးပို့နိုင်သည်။
* **🖥 Screen Sharing:** Call ပြောဆိုနေစဉ်အတွင်း မိမိ၏ Screen ကို တစ်ဖက်လူအား ပြသနိုင်သည်။
* **🔔 Real-time Notifications:** စာအသစ်ရောက်သည့်အခါ သို့မဟုတ် ဖုန်းလာသည့်အခါ အသိပေးချက်များ ရရှိမည်။
* **🔐 Secure Authentication:** JWT (JSON Web Token) နှင့် Bcrypt တို့ဖြင့် အကောင့်လုံခြုံရေးကို အဆင့်မြင့်စွာ တည်ဆောက်ထားသည်။

---

## 🛠 အသုံးပြုထားသော နည်းပညာများ (Tech Stack)

| Category | Technology |
| :--- | :--- |
| **Backend** | Node.js, Express.js |
| **Database** | MongoDB (Mongoose) |
| **Real-time Engine** | Socket.io |
| **P2P Connection** | WebRTC (Simple-Peer) |
| **File Storage** | Cloudinary (For Voice/Avatar) |
| **Security** | Helmet.js, JWT, Bcrypt |

---

## 🚀 စတင်အသုံးပြုရန် လမ်းညွှန် (Getting Started)

### ၁။ Installation
Project ကို Clone လုပ်ပြီး လိုအပ်သော Dependency များကို သွင်းပါ။
```bash
git clone [https://github.com/YourUsername/my-love-chat.git](https://github.com/YourUsername/my-love-chat.git)
cd my-love-chat
npm install
