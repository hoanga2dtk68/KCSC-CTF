# Externet Inplorer
![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/18b70de1-d236-4015-8ee3-074f58814b79)

Bài này khá đơn giản khi chỉ cần search google tìm tool và lấy flag

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/a273e4c0-e82a-4c73-9402-a233e269a494)

Có một bài viết ngay ở đầu

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/3f19af08-a171-4dcb-b8e8-d6db8f67387e)

Với thông tin trên thì có thể code tool phân tích hoặc sử dụng tool ở cuối bài

Sau khi đọc bài viết sẽ có link [Tool](https://dfir.blog/unfurl/)

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/de0ccfbd-1202-4ad7-a725-21f03dfc7959)

Flag: KCSC{2023-09-18_08:32:22.547027}

#idon'tknowthat

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/28b0b128-7572-41a7-843f-ca907666945c)

Khi mới vào có thể thấy rất rõ nguồn gốc cuộc tấn công với file được tải về 

![Screenshot 2024-05-14 015733](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/34d75a98-aaec-486b-bfb7-18d77565a604)

Nhưng tác giả đã xóa file zip đã được tải về tuy file zip vẫn còn trên máy do cơ chế lưu lại nhưng do không có pass nên không thể đi theo hướng này được

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/fa76ac27-e7e0-4191-8046-06191ddb436c)

Để phát hiện ra con loader ở trên máy được nằm ở đâu thì mình có 2 phương án

1. Grep theo extension encrypt trên máy ở đây là .KCSC(hơi unintended một chút) -> tìm được loader -> check các chỗ autorun

2. Thực hiện ghép thời gian tải về của file zip và check prefetch để lấy có file thực thi chạy thời gian gần đó để tìm cách mà hacker tạo persistence

Trong bài này mình sẽ trình bày theo phương án 2:

Với phần download bên trên sẽ biết được thời gian tải là 00:55:48

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/a9f3a04f-df67-4fe6-adce-63eadef3b8d5)

Với ảnh trên sau khi người dùng giải nén xong và thực hiện chạy file do tưởng nhầm là một file ảnh(png) với tên file là hinhsech.png.exe. Điều mình quan tâm ở đây là:
1. Tiến trình chạy hinhsech.png.exe có mở registry -> đây là chỗ mà hacker chọn để persistence
2. Hacker có sử dụng WEVTUTIL.EXE và chắc chắn để clear log evtx -> bỏ việc trace log evtx

Từ 1 có thể khẳng định part 1 là TT1547.001

Bây giờ mình sẽ thực hiện tìm ở trên list theo (link)[https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/privilege-escalation/untitled/registry-run-keys-startup-folder]

Và mình có đọc thêm ở trên (Microsoft)[https://learn.microsoft.com/en-us/mem/configmgr/develop/reference/core/clients/client-classes/sms_autostartsoftware-client-wmi-class]

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/5fdac139-89f9-4427-888c-e37b14d589c0)

Sau khi mình check HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows\load thấy tên file có vấn đề

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/458578a1-808e-4fd6-9fd1-766ec079620d)

Để ý kĩ trên tên file có chữ p có dấu chấm ở trên đầu -> fake notepad.exe -> loader

part 2: noteṗad.exe

Sử dụng detect it easy để biết file được compile bởi chương trình nào

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/b51efcf2-3ba4-4b89-8262-4d93afd21f22)

Sau khi đã biết được loader thì mình thực hiện reverse lại file xem noteṗad.exe thực hiện load file dll nào để encrypt file

![Screenshot 2024-05-14 022234](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/813ef705-ee00-451f-994e-b79a74063908)

Có thể thấy ngay rằng file dll được load là ntrdll.dll và cũng được drop tại System32

Tiếp tục sử dụng detect it easy để xem file ntrdll.dll được compile bằng ngôn ngữ gì

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/dc5ea7d1-c9da-4127-8b8b-56b5ed2c5139)

Với chương trình được compile bằng .NET mình sẽ sử dụng dotpeek để decompile

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/e829cea8-47a4-4a50-9cbc-cd11738c19da)

Với sub_novabeu sẽ chuyển key sang dạng xml và sub_gnoah sẽ gửi private key đến ip 192.168.248.130 với port là 9669

Ban đầu mình nghĩ sẽ khôi phục key bằng cách tác giả sử dụng một tool nào đó monitor nhưng sau khi đọc lại code thì đã tìm ra hướng khác

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/1010eb84-fc7f-40c8-9ef6-71a74ef48e02)

Còn hàm dưới chỉ có tác dụng check tên computer xem có trùng không để tránh trường hợp chạy thử bị encrypt. Sau khi check nếu trùng thì sẽ thực hiện encrypt các file được liệt kê sẵn: ".png",".pdf",".jpg",".docx",".xlsx",".xls",".doc",".pptx",".csv",".rtf",".jpeg",".html",".odt",".sql",".txt"

Và nếu chỉ dừng ở dòng Ransum.EncryptDirectory(folderPath, publicKey); thì thực sự không thể khôi phục private key để decrypt nên chú ý khi gọi hàm sub_huozi()

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/f56902c1-a558-4f17-b753-65cb45e07e68)

ở hàm sub_huozi() sẽ thực hiện tính thời gian chênh lệch giữa thời gian tạo ảnh main_background.jpg và 1/1/1970 12:00:00 sau đó thực hiện gọi hàm gethashcode và truyền cùng private key vào hàm sub_bqm để thực hiện xor 

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/b96cfa97-a5e7-4155-944a-7c07a1760619)

Sau đó hàm sub_benj sẽ thực hiện lưu vào cuối file main_background.jpg

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/fc94953f-f0eb-434d-a1a2-ca8f2abbf56f)

Từ đây mình chỉ cần tính lại hashcode để xor ngược lại với phần bị ghi ở cuối của file ảnh là sẽ lấy được private key để decrypt

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/9e73a4a0-21e2-4ab7-b990-70b5b13b4494)

Với file jpg có dấu hiệu kết thúc file là FF D9 mình chỉ cần lấy từ đó đến hết file và thực hiện xor để lấy lại private key

Ban đầu do không biết cơ chế trong (blog)[https://andrewlock.net/why-is-string-gethashcode-different-each-time-i-run-my-program-in-net-core/] này nên mình stuck khá lâu ở phần gethashcode do bị thay đổi theo thời gian

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/4917dd76-aebc-4f81-8f1e-148c26879f7e)

Sau khi sử dụng csc.exe để build thì mình không gặp tình trạng này nữa

```C#
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
class Program
{
    static void Main(string[] args)
    {
        sub_huozi();
    }

    private static void sub_huozi()
    {
      byte[] enc = File.ReadAllBytes("enc.dat");
      string str = "F:\\C___NONAME [NTFS]\\[root]\\Users\\khanhwibu\\Pictures\\main_background.jpg";
      int hashCode = ((long) (File.GetCreationTime(str) - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Local)).TotalSeconds).ToString().GetHashCode();
      Console.WriteLine(hashCode);
      byte[] bytes1 = BitConverter.GetBytes(hashCode);
      for (int index = 0; index < enc.Length; ++index)
        enc[index] ^= bytes1[index % bytes1.Length];
      File.WriteAllBytes("dec.dat", enc);
    }
}
```
Kết quả hash code sau khi chạy

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/eafa2e6f-1bde-485f-b348-c864b3405542)

Ban đầu mình có sử dụng web compiler online nhưng tính ra hashcode sai nên không thể decrypt

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/7bac4292-ef6a-4c29-bd6f-74ea95eaeb9a)

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/9fd2e783-6ec8-49a7-a2d5-cf882812c91d)

yeah thành công rồi bây giờ chỉ còn công việc decrypt để lấy part3 nữa là done

Dưới đây là source code để decrypt của mình
```C#
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
class Program
{
    static void Main(string[] args)
    {
        string folderPath = "Documents";
        string[] files = Directory.GetFiles(folderPath);
        string privateKeyXml = File.ReadAllText("dec.dat");
        var encFiles = files.Where(filePath => Path.GetExtension(filePath).Equals(".KCSC", StringComparison.OrdinalIgnoreCase));
        foreach (var encFile in encFiles)
        {
            DecryptFile(encFile, privateKeyXml);
        }
    }

    private static void DecryptFile(string filePath, string publicKeyXml)
    {
      using (RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider())
      {
        try
        {
          cryptoServiceProvider.FromXmlString(publicKeyXml);
          cryptoServiceProvider.ExportParameters(false);
          using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
          {
            if (fileStream.Length <= 256L)
            {
              byte[] numArray = new byte[fileStream.Length];
              fileStream.Read(numArray, 0, numArray.Length);
              byte[] bytes = cryptoServiceProvider.Decrypt(numArray, true);
              File.WriteAllBytes(Path.ChangeExtension(filePath, null), bytes);
            }
            else
            {
              using (MemoryStream memoryStream = new MemoryStream())
              {
                byte[] numArray = new byte[256];
                while (fileStream.Read(numArray, 0, numArray.Length) > 0)
                {
                  byte[] buffer = cryptoServiceProvider.Decrypt(numArray, true);
                  memoryStream.Write(buffer, 0, buffer.Length);
                }
                File.WriteAllBytes(Path.ChangeExtension(filePath, null), memoryStream.ToArray());
              }
            }
          }
          File.Delete(filePath);
        }
        catch (CryptographicException ex)
        {
          Console.WriteLine("Error encrypting file: " + ex.Message);
        }
      }
    }
}
```
Sau khi decrypt xong tìm được part3 ở file danhsachsv.xlsx

![image](https://github.com/hoanga2dtk68/KCSC-CTF/assets/110059218/b8f1204b-74c7-452c-894a-19fb59dca24f)

part 3: nho_lau_sach_man_hinh_truoc_khi_choi_ctf_ban_nhe_xxxnxx

Flag: KCSC{T1547.001_noteṗad.exe_nho_lau_sach_man_hinh_truoc_khi_choi_ctf_ban_nhe_xxxnxx}
