package com.example;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class FileController {
    private String secretKey;
    private int keySize = 16; // Default to 128-bit
    
    @Value("${file.upload-dir}")
    private String uploadDir;

    @Value("${spring.servlet.multipart.max-file-size}")
    private String maxFileSize;

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("key", secretKey != null ? secretKey : "Chưa có khóa");
        model.addAttribute("keySize", keySize);
        return "index";
    }

    @PostMapping("/generateKey")
    public String generateKey(@RequestParam(value = "keySize", defaultValue = "16") int size) {
        keySize = size;
        secretKey = generateRandomKey(keySize);
        return "redirect:/";
    }

    @PostMapping("/setKey")
    public String setKey(@RequestParam("customKey") String customKey, Model model) {
        if (customKey.length() != 16 && customKey.length() != 24 && customKey.length() != 32) {
            model.addAttribute("error", "Khóa phải có độ dài 16, 24 hoặc 32 ký tự");
            return "index";
        }
        secretKey = customKey;
        keySize = customKey.length();
        return "redirect:/";
    }

    @PostMapping("/encrypt")
    public String encryptFile(@RequestParam("file") MultipartFile file, Model model) {
        Path tempFile = null;
        Path encryptedFile = null;
        
        try {
            if (secretKey == null) {
                model.addAttribute("error", "Vui lòng tạo khóa trước!");
                return "index";
            }

            // Validate file size
            if (file.getSize() > parseMaxFileSize()) {
                model.addAttribute("error", "File quá lớn. Kích thước tối đa là " + maxFileSize);
                return "index";
            }

            // Validate file name
            String originalFilename = file.getOriginalFilename();
            if (originalFilename == null || originalFilename.contains("..")) {
                model.addAttribute("error", "Tên file không hợp lệ");
                return "index";
            }

            Path uploadPath = Paths.get(uploadDir);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            // Save uploaded file temporarily
            tempFile = uploadPath.resolve(originalFilename);
            file.transferTo(tempFile);

            // Read and encrypt file
            byte[] fileContent = Files.readAllBytes(tempFile);
            AES aes = new AES(secretKey);
            String encryptedContent = aes.encryptFile(fileContent);
            
            // Save encrypted file
            String encryptedFilename = "encrypted_" + originalFilename;
            encryptedFile = uploadPath.resolve(encryptedFilename);
            Files.write(encryptedFile, encryptedContent.getBytes());

            model.addAttribute("message", "Mã hóa thành công: " + encryptedFilename + 
                " | Thời gian: " + aes.getEncryptionTime() + " ns");
            model.addAttribute("filePath", encryptedFile.toAbsolutePath().toString());

        } catch (IOException e) {
            model.addAttribute("error", "Lỗi khi xử lý file: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            model.addAttribute("error", "Lỗi khi mã hóa: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Clean up temporary file
            if (tempFile != null && Files.exists(tempFile)) {
                try {
                    Files.delete(tempFile);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return "index";
    }

    @PostMapping("/decrypt")
    public String decryptFile(@RequestParam("file") MultipartFile file, Model model) {
        Path tempFile = null;
        Path decryptedFile = null;
        
        try {
            if (secretKey == null) {
                model.addAttribute("error", "Vui lòng tạo khóa trước!");
                return "index";
            }

            // Validate file size
            if (file.getSize() > parseMaxFileSize()) {
                model.addAttribute("error", "File quá lớn. Kích thước tối đa là " + maxFileSize);
                return "index";
            }

            // Validate file name
            String originalFilename = file.getOriginalFilename();
            if (originalFilename == null || originalFilename.contains("..")) {
                model.addAttribute("error", "Tên file không hợp lệ");
                return "index";
            }

            Path uploadPath = Paths.get(uploadDir);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            // Save uploaded file temporarily
            tempFile = uploadPath.resolve(originalFilename);
            file.transferTo(tempFile);

            // Read encrypted content
            byte[] encryptedBytes = Files.readAllBytes(tempFile);
            String encryptedContent = new String(encryptedBytes, "UTF-8");
            
            // Decrypt content
            AES aes = new AES(secretKey);
            byte[] decryptedContent = aes.decryptFile(encryptedContent);
            
            // Save decrypted file
            String decryptedFilename = "decrypted_" + originalFilename.replace("encrypted_", "");
            decryptedFile = uploadPath.resolve(decryptedFilename);
            Files.write(decryptedFile, decryptedContent);

            model.addAttribute("message", "Giải mã thành công: " + decryptedFilename + 
                " | Thời gian: " + aes.getDecryptionTime() + " ns");
            model.addAttribute("filePath", decryptedFile.toAbsolutePath().toString());

        } catch (IOException e) {
            model.addAttribute("error", "Lỗi khi xử lý file: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            model.addAttribute("error", "Lỗi khi giải mã: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Clean up temporary file
            if (tempFile != null && Files.exists(tempFile)) {
                try {
                    Files.delete(tempFile);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return "index";
    }

    private String generateRandomKey(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int index = (int) (Math.random() * chars.length());
            sb.append(chars.charAt(index));
        }
        return sb.toString();
    }

    private long parseMaxFileSize() {
        String size = maxFileSize.toUpperCase();
        long multiplier = 1;
        if (size.endsWith("KB")) {
            multiplier = 1024;
            size = size.substring(0, size.length() - 2);
        } else if (size.endsWith("MB")) {
            multiplier = 1024 * 1024;
            size = size.substring(0, size.length() - 2);
        } else if (size.endsWith("GB")) {
            multiplier = 1024 * 1024 * 1024;
            size = size.substring(0, size.length() - 2);
        }
        return Long.parseLong(size) * multiplier;
    }
}