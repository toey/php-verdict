# php-verdict

php-verdict เป็นเครื่องมือตัดสินว่าไฟล์ PHP เป็น webshell หรือ backdoor หรือไม่ เขียนด้วย Rust เครื่องมือให้คะแนนไฟล์จากหลายสัญญาณ (multi-signal) ได้แก่
signature, taint-flow, การคลายสตริงที่ซ่อนชื่อฟังก์ชัน (constant folding), ไฟล์ polyglot (PHP ที่ซ่อนหลังหัวไฟล์รูป/ZIP/PDF) และค่าสถิติของตัวไฟล์
เครื่องมือ**อ่านไฟล์จากดิสก์อย่างเดียว ไม่รัน PHP ใดๆ** และสแกนได้ราว 11,000 ไฟล์ต่อวินาที

```
CRITICAL  180  /home/x/public_html/wp-admin/css/colors/modern/colors-rtl.css.php :: PHP code inside an image/archive file (polyglot, tag at byte 9252) (+100); upload saved under the client-supplied file name ($_FILES name) (+60); packed one-liner, longest line 5026B (+20)
```

## ระดับคะแนน

คะแนนของไฟล์คือผลรวมคะแนนของทุกกฎที่ตรง

| ระดับ | คะแนน | ความหมาย |
|---|---|---|
| `CRITICAL` | ≥ 100 | เป็นของมุ่งร้ายแน่นอน กักไฟล์ได้เลย |
| `SUSPECT` | 60–99 | น่าสงสัยมาก ควรให้คนตรวจ |
| `WARN` | 30–59 | มีสัญญาณประกอบอย่างเดียว |
| `CLEAN` | < 30 | ไม่พบสิ่งผิดปกติ |

## ติดตั้ง

ต้องใช้ Rust ≥ 1.85 (edition 2024)

```bash
git clone git@github.com:toey/php-verdict.git
cd php-verdict
./install.sh                    # build + self-test + ติดตั้งไปที่ /usr/local/bin/php-verdict
```

ตัวเลือกของ `install.sh`:

| ตัวเลือก | ทำอะไร |
|---|---|
| (ไม่ใส่) | ติดตั้งไปที่ `/usr/local/bin/php-verdict` |
| `--dest PATH` | ติดตั้งไปที่ path อื่น |
| `--honeypot` | ติดตั้งไปที่ `/opt/honeypot/php-verdict-rs/target/release/php-verdict` ซึ่งเป็น path ที่ scanner ของ honeypot เรียกใช้ และคัดลอก source ไปไว้ข้างกัน |
| `--install-rust` | ถ้ายังไม่มี cargo ให้ลง Rust ผ่าน rustup ก่อน |
| `--rollback [--dest PATH]` | คืนไฟล์ binary ตัวก่อนหน้าจาก backup ตัวล่าสุด |

ขั้นตอนของ installer:
1. build ด้วย `nice` เพื่อไม่ให้เครื่องที่ให้บริการเว็บช้าลง
2. รัน `tests/run.sh` ถ้าเทสไม่ผ่านจะหยุดทันที และไม่แตะไฟล์ที่ติดตั้งอยู่
3. backup ไฟล์เดิมเป็น `<dest>.bak-YYYYmmdd-HHMMSS`
4. คัดลอกไฟล์ใหม่ไปไว้ข้างๆ แล้วใช้ `mv` สลับเข้าที่ ทำให้ scanner ที่กำลังรันอยู่ไม่มีโอกาสเจอไฟล์ที่เขียนไม่ครบ

ถ้าจะ build เองโดยไม่ใช้ installer:

```bash
cargo build --release
tests/run.sh target/release/php-verdict
```

## วิธีใช้

```bash
php-verdict FILE...                 # แสดงเฉพาะไฟล์ที่ไม่ CLEAN บรรทัดละไฟล์: LEVEL score path :: เหตุผล 3 ข้อแรก
php-verdict --all FILE...           # แสดงไฟล์ CLEAN ด้วย
php-verdict --explain FILE...       # แจกแจงคะแนนละเอียด (ดูหัวข้อถัดไป)
php-verdict --json FILE...          # JSON บรรทัดละไฟล์ มี breakdown, evidence, metrics
php-verdict --stdin [--threads N]   # รับรายชื่อไฟล์จาก stdin (คั่นด้วย NUL หรือขึ้นบรรทัดใหม่)
```

สแกนทั้งเครื่องโดยไม่ให้เว็บช้า:

```bash
find /home/*/domains/*/public_html -type f \( -name '*.php*' -o -name '*.phtml' -o -name '*.inc' \) -size -3M -print0 \
  | nice -n 19 ionice -c3 php-verdict --stdin --threads 6 > verdict.txt
grep ^CRITICAL verdict.txt
```

### `--explain`: แจกแจงคะแนนละเอียด

```
$ php-verdict --explain s1.php
── CRITICAL score 200  (CRITICAL≥100 SUSPECT≥60 WARN≥30)
file: s1.php
  +100  PHP code inside an image/archive file (polyglot, tag at byte 54)
  +100  fetched content executed with eval('?>'.…) (remote code loader)
  L3: $Url = $_GET['url'];
  L8: $output = curl_exec($ch);
  L10: echo eval('?>'.$output);
  metrics: compress=0.6884 decoders=0 entropy=5.0896 first_line=45 ... size=292 superglobals=1
```

- **`+N` แต่ละบรรทัด** คือกฎที่ตรงกับไฟล์ และคะแนนรวมเท่ากับผลรวมของบรรทัดเหล่านี้
- **`L<n>:`** คือบรรทัดหลักฐาน แสดงได้สูงสุด 4 บรรทัด เป็นบรรทัดที่มี sink, decoder หรือ superglobal เครื่องมือข้ามบรรทัดที่เป็นคอมเมนต์ และตัดเศษ binary ของหัว polyglot ออก
- **`metrics`** คือค่าสถิติที่กฎกลุ่ม statistical ใช้ เช่น entropy, index of coincidence และความยาวบรรทัด/คำที่ยาวที่สุด

แต่ละไฟล์จะออกมาเป็นหลายบรรทัดติดกันโดยไม่มีบรรทัดว่างคั่น จึงนำไปต่อท้ายข้อความแจ้งเตือนแบบ block (เช่น Telegram) ได้ตรงๆ
ส่วน `--json` ให้ข้อมูลชุดเดียวกันในฟิลด์ `breakdown` `[{points, rule}]`, `evidence` `[{line, text}]` และ `metrics`

## กฎหลัก

| กลุ่ม | ตัวอย่างกฎ | คะแนน |
|---|---|---|
| Fingerprint | ตระกูล webshell ที่รู้จัก, Family-K, EtherHiding JS stub, blockchain C2 (`eth_call`), Wordfence ปลอม | 100 |
| Taint | user input เข้า execution sink ตรงๆ, superglobal ถูกเรียกเป็นฟังก์ชัน, decoder ทำงานกับ input | 70–100 |
| Folding (v6) | คลาย `'lit'` / `"\x..\NNN"` / `chr()` / `strrev` / `str_rot13` / `base64_decode` / `hex2bin` ... แล้วนำผลไปเทียบกับรายชื่อ sink: ได้ exec sink +100, ได้ decoder +60 | 60/100 |
| Polyglot (v6) | PHP อยู่หลังหัวไฟล์ ZIP/JPEG/PNG/GIF/PDF/gzip +100, อยู่หลัง binary อื่น +60 (กฎนี้ทำงานแม้ tag `<?php` จะอยู่เลย 4 KB แรกไป) | 60/100 |
| Loader (v6) | `eval('?>'.curl_exec(...))`, ตารางชื่อฟังก์ชันอันตรายที่เขียนเป็นสตริง hex | 100 |
| Uploader (v6) | `copy`/`move_uploaded_file` ไปยัง `$_FILES[..]['name']` (ใช้ชื่อไฟล์ที่ client ส่งมา) | 60 |
| Behinder/Godzilla | AES-decrypt request body แล้ว exec, XOR keystream, eval ใน `*invoke` | 70–90 |
| Stego / homoglyph | ถอดรหัส whitespace-binary, ชื่อไฟล์ที่เป็น homoglyph ของ core, Unicode bidi ในชื่อไฟล์ | 45–100 |
| Statistics | entropy/IC ผิดปกติ, ไฟล์ที่ไม่มีเครื่องหมายวรรคตอน, base64 blob ยาว, บรรทัดแรกยาวผิดปกติ | 20–70 |

ข้อยกเว้น (`EXCLUDE_PATH`) ข้ามเฉพาะไฟล์ data ที่รู้จัก ใน `wflogs/` จะข้ามแค่ชื่อไฟล์ของ Wordfence 10 ชื่อ เพราะเคยมีผู้โจมตีซ่อน shell ไว้ในโฟลเดอร์นี้

## ทดสอบ

```bash
tests/run.sh [path/to/php-verdict]
```

`tests/expected.txt` ระบุระดับขั้นต่ำที่ไฟล์ใน `tests/fixtures/` แต่ละไฟล์ต้องได้ และไฟล์ใน `clean/` ต้องได้ `CLEAN`
fixture ใน `bad/` เป็น webshell บรรทัดเดียวที่ใช้งานได้จริง **ห้ามวางไว้ใน web root**

ก่อนนำ engine เวอร์ชันใหม่ขึ้นใช้งาน ให้ตรวจสองอย่าง:
1. สแกนชุดไฟล์ PHP ทางการ (WordPress core + plugin จาก wordpress.org ประมาณ 280k ไฟล์) ด้วย engine เดิมและ engine ใหม่ แล้ว diff ผลกัน ต้องได้ 0 บรรทัด
2. สแกนไฟล์ในโฟลเดอร์ quarantine ต้องได้ระดับเดิมหรือสูงกว่า

v6 ผ่านทั้งสองข้อ: diff 0 บรรทัดบนไฟล์ทางการ 282,636 ไฟล์ และไฟล์ polyglot ที่กักไว้ 68 ไฟล์ได้ CRITICAL 67 / SUSPECT 1 (ส่วน v5 ให้ CLEAN ทั้งหมด)

## ประวัติ

- **v6.0.0**
  - เพิ่ม constant folding ชื่อ sink
  - เพิ่มการตรวจ polyglot ที่ทำงานก่อน PHP gate
  - เพิ่มกฎ remote loader, hex function table และ raw-name uploader
  - `--explain` และ `breakdown`/`evidence` ใน JSON
  - จำกัดข้อยกเว้น `wflogs/` เหลือเฉพาะชื่อไฟล์ของ Wordfence
  - เปลี่ยนเป็น edition 2024
- **v5.0.0**: port จาก `php-verdict.py` v4 มาเป็น Rust ให้ผลตรงกับ Python 0-diff และเร็วขึ้นราว 600 เท่า
