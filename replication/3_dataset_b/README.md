# Dataset B v2 – Controlled Attack Scenarios

## Mục tiêu
Benchmark ExfilGuard trên các GitHub Actions workflow được kiểm soát, có ground truth xác định trước.

## Quy mô
30 test cases:
- 18 exploit
- 12 benign
- 6 scenario bắt buộc, mỗi scenario có 3 exploit + 2 benign.
- difficulty: easy / medium / hard.

## 6 scenario
1. Direct Secret -> curl
2. Secret -> variable -> curl
3. Secret -> Bash -> HTTP
4. Secret -> Python -> requests
5. Secret -> Node.js -> HTTP
6. Secret -> DNS-related sink

## Điểm cải tiến so với v1
- Hard negatives: whitelist/official destination, masked secret, hash-only, dummy variable.
- Obfuscation/transformation: base64, concatenation, multi-hop propagation.
- Embedded Bash/Python/Node.js.
- Ground truth có expected source-to-sink path và difficulty.
- CSV được ghi UTF-8 không BOM.

## Ground-truth convention
- exploit = có đường taint từ secret source tới sink đáng ngờ.
- benign = không có đường taint tới sink, hoặc flow được policy xác định là allowed.
- Với hash/base64: dataset giữ taint trong ground truth nếu dữ liệu biến đổi vẫn có thể mang thông tin từ secret. Nếu framework định nghĩa hash là sanitizer/barrier, phải ghi rõ policy trong paper và benchmark theo policy đó.

## An toàn
- Không dùng secret thật.
- Dùng `example.invalid`, domain dành riêng cho ví dụ.
- Các workflow chủ yếu phục vụ static analysis; không cần gửi dữ liệu thật ra Internet.
