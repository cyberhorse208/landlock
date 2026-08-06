package com.vivo.landlocktest;

import android.content.Context;
import android.icu.text.SimpleDateFormat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class FileUtils {
    private static Context ucontext = null;
    private static String messageFile = "FlowerResults.txt";

    public static void writeStringToFilePath(String filePath, String content) throws IOException {
        File file = new File(filePath);
        FileWriter writer = new FileWriter(file, true);
        writer.append(content);
        writer.close();
    }

    public static List<String> readStringFromFilePath(String filePath) throws IOException {
        return readStringFromFilePath(filePath, 0);
    }

    public static List<String> readStringFromFilePath(String filePath, int maxBytes) throws IOException {
        List<String> lines = new ArrayList<>();
        File file = new File(filePath);

        if (!file.exists()) {
            return lines;
        }

        if (maxBytes <= 0) {
            FileReader reader = new FileReader(file);
            BufferedReader bufferedReader = new BufferedReader(reader);
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                lines.add(line);
            }
            bufferedReader.close();
            reader.close();
        } else {
            FileInputStream fis = new FileInputStream(file);
            byte[] buffer = new byte[maxBytes];
            int readLen = fis.read(buffer);
            fis.close();
            if (readLen > 0) {
                String content = new String(buffer, 0, readLen);
                String[] splitLines = content.split("\n");
                for (String l : splitLines) {
                    lines.add(l);
                }
            }
        }
        return lines;
    }

    public static void init(Context context, String filename) {
        ucontext = context;
        messageFile = filename;
    }

    public static String getCurrentTimeString(String fmt) {
        if (fmt.isEmpty()) {
            fmt = "yyyy-MM-dd HH:mm:ss";
        }
        SimpleDateFormat sdf = new SimpleDateFormat(fmt, Locale.getDefault());
        Date currentDate = new Date();
        return sdf.format(currentDate);
    }

    public static void writeStringToMessageFile(String content) throws IOException {
        content = getCurrentTimeString("") + ": " + content;
        writeStringToFile(ucontext, messageFile, content);
    }

    public static void writeStringToFile(Context context, String fileName, String content) throws IOException {
        // Get the app-specific external storage directory
        File directory = context.getExternalFilesDir(null);

        if (directory != null) {
            File file = new File(directory, fileName);

            // Check if the file exists
            boolean fileExists = file.exists();

            // Open a FileWriter in append mode
            FileWriter writer = new FileWriter(file, true);

            // If the file exists and is not empty, add a new line
            if (fileExists && file.length() > 0) {
                writer.append("\n");
            }

            writer.append(content);
            writer.close();
        }

    }

    public static List<String> readStringFromMessageFile() {
        return readStringFromFile(ucontext, messageFile);
    }

    public static List<String> readStringFromFile(Context context, String fileName) {
        List<String> lines = new ArrayList<>();

        try {
            File directory = context.getExternalFilesDir(null);

            if (directory != null) {
                File file = new File(directory, fileName);

                // Checking if the file exists
                if (!file.exists()) {
                    return lines; // File doesn't exist then return an empty list
                }
                // Opening a FileReader to read the file
                FileReader reader = new FileReader(file);
                BufferedReader bufferedReader = new BufferedReader(reader);
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    lines.add(line);
                }
                // Closing the readers
                bufferedReader.close();
                reader.close();
            }
        } catch (IOException e) {
            e.printStackTrace(); // Handle the exception as needed
        }

        return lines;
    }


    public static void clearMessageFileContents() {
        try {
            File directory = ucontext.getExternalFilesDir(null);

            if (directory != null) {
                File file = new File(directory, messageFile);

                // Checking if the file exists
                if (!file.exists()) {
                    // File doesn't exist, so there's nothing to clear
                    return;
                }

                // Opens a FileWriter with append mode set to false (this will clear the file)
                FileWriter writer = new FileWriter(file, false);
                writer.write(""); // Write an empty string to clear the file
                writer.close();
            }
        } catch (IOException e) {
            e.printStackTrace(); // Handle the exception as needed
        }
    }

    public static void createEmptyMessageFile(String fileName) {
        try {
            File file = new File(fileName);

            // Create the file if it doesn't exist
            if (!file.exists()) {
                file.createNewFile();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean copyFile(String srcfilePath, String destFilePath, StringBuilder result){
        File sourceFile = new File(srcfilePath);
        File destFile = new File(destFilePath);

        // 检查源文件是否存在
        if (!sourceFile.exists()) {
            result.append("错误: 源文件不存在 - ").append(srcfilePath).append("\n");
        } else {
            // 创建目标目录（如果不存在）
            destFile.getParentFile().mkdirs();

            // 使用文件流进行拷贝
            try {
                FileInputStream mInputStream = new FileInputStream(sourceFile);
                FileOutputStream mOutputStream = new FileOutputStream(destFile);
                byte[] mBuffer = new byte[1024];
                int mLength;
                while ((mLength = mInputStream.read(mBuffer)) > 0) {
                    mOutputStream.write(mBuffer, 0, mLength);
                }

                result.append("成功: 文件已从 ").append(srcfilePath)
                        .append(" 拷贝到 ").append(destFilePath).append("\n");
                return true;
            } catch (Exception e) {
                result.append("错误: ").append(e.getMessage()).append("\n");
            }
        }
        return false;
    }

}
