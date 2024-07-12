package com.chico.plugins;

import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.TaskAction;
import org.gradle.api.file.DirectoryProperty;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.fornwall.jelf.ElfFile;
import net.fornwall.jelf.ElfSection;

public abstract class NativeCodeProtectTask extends DefaultTask {

    @InputDirectory
    public abstract DirectoryProperty getNativeDir();

    @TaskAction
    public void action() {
        try {
            Files.walk(getNativeDir().getAsFile().get().toPath())
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith("libelfencrytest.so"))
                    .forEach(path -> {
                        try {
                            processFile(path);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void processFile(Path path) throws Exception {
        File file = path.toFile();
        ElfFile elfFile = ElfFile.from(file);
        for (int i = 0; i < elfFile.e_shnum; i++) {
            ElfSection section = elfFile.getSection(i);
            String sectionName = section.header.getName();
            if (sectionName == null || !sectionName.equals(".text")) {
                continue;
            }

            try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
                FileChannel channel = raf.getChannel();
                long offset = section.header.sh_offset;
                long size = section.header.sh_size;
                System.out.println("Header = " + section.header.toString() + ", offset = " + offset + ", size = " + size);

                ByteBuffer buffer = ByteBuffer.allocate((int) size);
                channel.read(buffer, offset);
                byte[] data = buffer.array(); // .text section data
                // System.out.println("Original .text section first 64 bytes: " + bytesToHex(data, 64));

                byte[] key = "JuanCarlos@41273JuanCarlos@41273".getBytes(StandardCharsets.UTF_8); // 256-bit key
                byte[] iv = new byte[16]; // 128-bit IV, can be all zero for simplicity
                byte[] encryptedData = encrypt(data, key, iv);
                System.out.println("Encrypted .text size " + encryptedData.length);

                ByteBuffer outputBuffer = ByteBuffer.wrap(encryptedData);
                channel.write(outputBuffer, offset);
                channel.force(true);
                System.out.println("Successfully encrypted the SO file: " + file.getAbsolutePath());
            }
            break;
        }
    }

    private byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    /*private static String bytesToHex(byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length && i < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        return sb.toString();
    }*/
}
