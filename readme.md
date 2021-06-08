---
title: "Report Đồ án TH: Cơ chế hoạt động của mã độc"
date: "2021-06-08"
---

## Thông tin nhóm và đồ án

### Thông tin nhóm:

Nhóm 2:

- Nguyễn Xuân Khang - 18520071
- Nguyễn Thanh Gia Truyền - 18521576

### Thông tin đề tài:

Đề tài 2: DLL Injection

#### Quá trình thực hiện:

**Giai đoạn đầu - lên ý tưởng:** ngay khi nhận được đề tài này, mình cũng vừa gặp một challenge RE của FLARE On 2016, đó là một challenge ransomware hoàn toàn mới mẻ, và quá khó với level 2 của nó. Mình không tìm được lời giải và sau đó đọc write-up mới hiểu hết hoàn toàn ý tưởng của tác giả muốn gửi gắm.

Con người ta là vậy, luôn muốn ghi nhớ những vết thương, những lần thua cay điếng người. Mình cũng vậy, mình gà quá, tệ quá, mới challenge 2 mà phải đi xem writeup rồi. Yay, nên mình mới nhân cái đồ án thực hành này, tạo lại một ransomware và áp dụng nó vào kỹ thuật DLL Injecton.

Nội dung cơ bản của đồ án:

#### DLLInjector.exe

Chắc chắn một simple Injector khá là phổ biến, nó sẽ đóng chức năng như một thằng trung gian để inject DLL của mình vào một process target. Ở đây mình chọn là Unikey( 32 bit).

Có rất nhiều con đường, cách thức để thực hiện DLL Injection như  
thông qua các Registry, kỹ thuật Windows Hooking, sử dụng DLL như là  
một debugger....

Trong task này, sẽ cụ thể hóa một trong con đường mạnh nhất, sử  
dụng phổ biến nhất hiện này đó là thông qua một application, thực hiện tạo một thread trong target process( process sẽ bị DLL Injection), vì Windows OS hỗ trợ việc tạo một thread cho một tiến trình bởi hàm  
CreateRemoteThread() nên sẽ dễ dàng thực hiện được việc này( phải đảm  
bảo đầy đủ có các đặc quyền với target process), từ thread được tạo mới đó, chúng ta sẽ load file DLL vào để thực hiện injection. Các bước cụ thể của kỹ thuật DLL Injection sử dụng Remote Thread sẽ được thực hiện như sau:

- lấy PID của UniKey 4.2 RC4 và thực hiện mở process

![](https://ph0xen1x0.files.wordpress.com/2021/06/image.png?w=1024)

- Cấp phát vùng nhớ trong injected process( target process) sử dụng  
    hàm VirtualAllocEx

![](https://ph0xen1x0.files.wordpress.com/2021/06/image-1.png?w=1024)

- Sao chép đường dẫn DLL chứa malicious code vào vùng nhớ cấp  
    phát ở bước 1 sử dụng hàm WriteProcessMemory

![](https://ph0xen1x0.files.wordpress.com/2021/06/image-2.png?w=1024)

- Tạo luồng mới trong tiến trình dự định injected sử dụng hàm  
    CreateRemoteThread gọi LoadLibraryA trong kernel32.dll, truyền  
    nó vào địa chỉ của bộ nhớ đã được cấp phát ở bước 1. Ngay tại  
    bước này, malicious DLL do chúng ta viết đã được injected vào  
    target process

![](https://ph0xen1x0.files.wordpress.com/2021/06/image-3.png?w=975)

- Sau khi thực hiện xong malicious code truyền vào, thread truyền  
    vào sẽ kết thúc, chúng ta phải xóa DLL còn trong memory  
    space được cấp phát ở bước đầu tiên, giải phóng vùng  
    nhớ sử dụng hàm VirtualFreeEx

![](https://ph0xen1x0.files.wordpress.com/2021/06/image-4.png?w=1024)

#### EncryptFile.dll

Mình sẽ tạo một DLL có chức năng như một simple ransomware mã hóa tất cả các file trong thư mục Briefcase( đây thường là thư mục lưu các tài liệu việc làm, hợp đồng quan trọng của các cá nhân, tổ chức, doanh nghiệp v.v.) như sau:

- Đầu tiên mình sử dụng một key( thông thường key này sẽ được xor hay gì đó để phức tạp hơn, nhưng đây để cho đơn giản mình bỏ nó trong source code luôn :v ):

![](https://ph0xen1x0.files.wordpress.com/2021/06/image-5.png?w=1024)

- Như thấy trong hình, key = `"Malware_machenism_courses_is_so_funny"` sau đó sẽ được đem đi hash và sử dụng như là key cho thuật toán AES-256:

- Đây là hàm trung tâm để lặp qua tất cả các file và các folder trong Briefcase directory, nếu nó gặp một file thì đầu tiên sẽ:
    - **`MD5HashFileReadName() function:`** sử dụng MD5 hash để hash chuỗi tạo bởi tên file và extension của file đó, đây chính là IV cho thuật toán AES-256

![](https://ph0xen1x0.files.wordpress.com/2021/06/image-6.png?w=1024)

- **`EncryptFunc()`**: key đã có rồi, IV cũng có rồi, hàm này sẽ là hàm trung tâm mã hóa một file của chúng ta: nó sẽ đọc tất cả các byte của file vào một buffer, tạo một Heap để lưu ciphertext, và sau khi đã mã hóa qua tất cả các block của file, nó thực hiện ghi lại vào file ban đầu:

![](https://ph0xen1x0.files.wordpress.com/2021/06/image-7.png?w=1024)

- Hãy để ý snipcode ở trên, mình có comment một câu lệnh, đó chính là lệnh sẽ decrypt một file về nội dung ban đầu, nếu như uncomment câu lệnh này, và comment hàm CryptEncrypt bên dưới, mình có thể tạo ra một DLL thứ 2 với mục đích decrypt tất cả file về ban đầu

encRet = CryptDecrypt(\*(DWORD\*)hKey, 0, boolFinal, 0, (BYTE\*)lpBuffer, &NumberOfBytesRead);

- Đó là tất cả những gì mà DLL mình sẽ thực hiện. Giờ chỉ việc tiến hành demo và kiểm tra kết quả thôi
- Link video demo: **[DLL Injection: Demo DLL Ransomware](https://youtu.be/VZpifmgw0GY)**
