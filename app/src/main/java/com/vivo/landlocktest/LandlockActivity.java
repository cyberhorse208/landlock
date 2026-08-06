
package com.vivo.landlocktest;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.vivo.kmirrors.security.Landlock;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;

public class LandlockActivity extends AppCompatActivity {
    private final static String TAG = "LandlockActivity";
    private String readfilename = "";
    private String writefilename = "";
    private String listen_port_allowed = "";
    private String listen_port_try = "";
    private int listen_timeout = 1000; // ms
    private String connect_port_allowed = "";
    private String connect_port_try = "";
    private String connect_ip_try = "";
    private int connect_timeout = 1000;//ms

    private void LoadFileArgs() {
        EditText ed_landlock_read_filename_try = findViewById(R.id.ed_landlock_read_filename_try);
        EditText ed_landlock_write_filename_try = findViewById(R.id.ed_landlock_write_filename_try);

        writefilename = ed_landlock_write_filename_try.getText().toString().trim();
        if (writefilename.isEmpty()) {
            Toast.makeText(LandlockActivity.this, getString(R.string.msg_enter_read_filename), Toast.LENGTH_SHORT).show();
        }

        readfilename = ed_landlock_read_filename_try.getText().toString().trim();
        if (writefilename.isEmpty()) {
            Toast.makeText(LandlockActivity.this, getString(R.string.msg_enter_write_filename), Toast.LENGTH_SHORT).show();
        }
    }
    private boolean LoadTestNetArgs(){
        EditText ed_landlock_listen_port_try = findViewById(R.id.landlock_listen_port_try);
        EditText ed_landlock_connect_port_try = findViewById(R.id.landlock_connect_port_try);
        EditText ed_landlock_connect_ip_try = findViewById(R.id.landlock_connect_ip_try);
        EditText ed_landlock_connect_timeout = findViewById(R.id.landlock_connect_timeout);
        EditText ed_landlock_listen_timeout = findViewById(R.id.landlock_listen_timeout);

        int jobCount = 2;

        listen_port_try = ed_landlock_listen_port_try.getText().toString().trim();
        if (listen_port_try.isEmpty()) {
            Toast.makeText(LandlockActivity.this, getString(R.string.msg_no_listen_port), Toast.LENGTH_SHORT).show();
            jobCount--;
        }
        String landlock_listen_timeout = ed_landlock_listen_timeout.getText().toString().trim();
        if(!landlock_listen_timeout.isEmpty()){
            listen_timeout = Integer.valueOf(landlock_listen_timeout);
        }

        connect_port_try = ed_landlock_connect_port_try.getText().toString().trim();
        connect_ip_try = ed_landlock_connect_ip_try.getText().toString().trim();
        if (connect_port_try.isEmpty() || connect_ip_try.isEmpty()) {
            Toast.makeText(LandlockActivity.this, getString(R.string.msg_no_connect_port), Toast.LENGTH_SHORT).show();
            jobCount--;
        }
        String landlock_connect_timeout = ed_landlock_connect_timeout.getText().toString().trim();
        if(!landlock_connect_timeout.isEmpty()){
            connect_timeout = Integer.valueOf(landlock_connect_timeout);
        }

        return jobCount != 0;
    }

    private boolean LoadLandLockNetArgs(){
        EditText ed_landlock_listen_port_allowed = findViewById(R.id.landlock_listen_port_allowed);
        EditText ed_landlock_connect_port_allowed = findViewById(R.id.landlock_connect_port_allowed);

        int jobCount = 2;
        listen_port_allowed = ed_landlock_listen_port_allowed.getText().toString().trim();
        if (listen_port_allowed.isEmpty()) {
            jobCount--;
            Toast.makeText(LandlockActivity.this, getString(R.string.msg_no_listen_port_allowed), Toast.LENGTH_SHORT).show();
        }

        connect_port_allowed = ed_landlock_connect_port_allowed.getText().toString().trim();
        if (connect_port_allowed.isEmpty()) {
            Toast.makeText(LandlockActivity.this, getString(R.string.msg_no_connect_port_allowed), Toast.LENGTH_SHORT).show();
            jobCount--;
        }

        return jobCount != 0;
    }

    private void checkThenAdd(Landlock landlock, ArrayList<String> paths, String path) {
        int ret = landlock.canBeLandlock(path);
        if (ret == 0) {
            paths.add(path);
            Log.d(TAG, path + " can be landlocked\n");
        } else {
            Log.d(TAG, path + " can't be landlocked for reason " + String.valueOf(ret) + "\n");
        }
    }

    private String setLandlockFileRules(Landlock landlock){
        String message = "";
        EditText ed_landlock_RO_path_allowed = findViewById(R.id.landlock_RO_path_allowed);
        EditText ed_landlock_RW_path_allowed = findViewById(R.id.landlock_RW_path_allowed);

        ArrayList<String> roPaths = new ArrayList<>(), rwPaths = new ArrayList<>();
        String inputContent = ed_landlock_RO_path_allowed.getText().toString().trim();
        String[] parts = inputContent.split(":");

        for (String part : parts) {
            String trimmedPart = part.trim();
            if (!trimmedPart.isEmpty()) {
                checkThenAdd(landlock, roPaths, trimmedPart);
            }
        }

        inputContent = ed_landlock_RW_path_allowed.getText().toString().trim();
        parts = inputContent.split(":");

        for (String part : parts) {
            String trimmedPart = part.trim();
            if (!trimmedPart.isEmpty()) {
                checkThenAdd(landlock, rwPaths, trimmedPart);
            }
        }

        message += getString(R.string.msg_prepare_rules);
        message += getString(R.string.msg_ro_dirs) + roPaths.toString() + "\n";
        message += getString(R.string.msg_rw_dirs) + rwPaths.toString() + "\n";

        int ret = landlock.SetFileRules(roPaths, rwPaths);
        if (ret == 0) {
            message += getString(R.string.msg_file_rules_ok);
        } else {
            message += getString(R.string.msg_file_rules_fail) + String.valueOf(ret) + getString(R.string.msg_landlock_not_active);
        }
        return message;
    }

    private String setLandlockNetRules(Landlock landlock){
        String message = "";
        ArrayList<String> listen_port_allowed_array = new ArrayList<>(), connect_port_allowed_array = new ArrayList<>();
        String[] parts = listen_port_allowed.split(":");
        for (String part : parts) {
            String trimmedPart = part.trim();
            if (!trimmedPart.isEmpty()) {
                listen_port_allowed_array.add(trimmedPart);
            }
        }
        parts = connect_port_allowed.split(":");
        for (String part : parts) {
            String trimmedPart = part.trim();
            if (!trimmedPart.isEmpty()) {
                connect_port_allowed_array.add(trimmedPart);
            }
        }

        message += getString(R.string.msg_prepare_rules);
        message += getString(R.string.msg_listen_ports) + listen_port_allowed_array + "\n";
        message += getString(R.string.msg_connect_ports) + connect_port_allowed_array + "\n";

        int ret = landlock.SetPortRules(listen_port_allowed_array, connect_port_allowed_array);
        if (ret == 0) {
            message += getString(R.string.msg_net_rules_ok);
        } else {
            message += getString(R.string.msg_net_rules_fail) + String.valueOf(ret) + getString(R.string.msg_landlock_not_active);
        }
        return message;
    }

    private String readFileContent(String filename) {
        String message = "";
        message += getString(R.string.msg_try_read_file) + filename + getString(R.string.msg_file_content);
        try {
            List<String> fileContent = FileUtils.readStringFromFilePath(filename, 100);
            if (!fileContent.isEmpty()) {
                message += String.join("\n", fileContent);
            }
        } catch (Exception e) {
            message += e.toString();
        }
        return message;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_landlock);
        ActionBar actionBar = getSupportActionBar();
        actionBar.setTitle("Landlock");

        TextView text_output = findViewById(R.id.landlock_text_output);
        text_output.setMovementMethod(ScrollingMovementMethod.getInstance());

        requestStoragePermissions();

        try {
            FileUtils.init(LandlockActivity.this, "message.txt");
            FileUtils.writeStringToMessageFile("just make sure file path exist!!");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        File externalFilesDir = getExternalFilesDir(null);
        if (externalFilesDir != null) {
            File readFile = new File(externalFilesDir, "read.txt");
            File writeFile = new File(externalFilesDir, "write.txt");
            try {
                if (!readFile.exists()) {
                    readFile.createNewFile();
                    Log.d(TAG, "created: " + readFile.getAbsolutePath());
                }
                if (!writeFile.exists()) {
                    writeFile.createNewFile();
                    Log.d(TAG, "created: " + writeFile.getAbsolutePath());
                }
            } catch (IOException e) {
                Log.e(TAG, "Failed to create test files: " + e.getMessage());
            }
        }

        Landlock landlock = new Landlock();

        TextView text_output_version = findViewById(R.id.tv_landlock_version_output);
        Button btn_landlock_getversion = findViewById(R.id.btn_landlock_getversion);
        btn_landlock_getversion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = getString(R.string.msg_abi_version) + landlock.getVersion();
                text_output_version.setText(s);
            }
        });

        EditText et_input_content = findViewById(R.id.landlock_input_content);
        Button btn_landlock_write_content = findViewById(R.id.btn_landlock_write_content);
        btn_landlock_write_content.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EditText ed_landlock_write_filename_try = findViewById(R.id.ed_landlock_write_filename_try);
                writefilename = ed_landlock_write_filename_try.getText().toString().trim();
                if (writefilename.isEmpty()) {
                    Toast.makeText(LandlockActivity.this, getString(R.string.msg_enter_filename_first), Toast.LENGTH_SHORT).show();
                }
                String inputContent = et_input_content.getText().toString().trim();
                try {
                    FileUtils.writeStringToFilePath(writefilename, inputContent);
                    String message = getString(R.string.msg_content_written) + writefilename;
                    text_output.setText(message);
                } catch (IOException e) {
                    text_output.setText(e.toString());
                }
            }
        });

        RadioGroup radioGroup = findViewById(R.id.radio_group);
        radioGroup.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.radio_btn_enable) {
                Toast.makeText(LandlockActivity.this, getString(R.string.msg_thread_enable_ll), Toast.LENGTH_SHORT).show();
            } else if (checkedId == R.id.radio_btn_disable) {
                Toast.makeText(LandlockActivity.this, getString(R.string.msg_thread_disable_ll), Toast.LENGTH_SHORT).show();
            }
        });
        RadioGroup radioGroup2 = findViewById(R.id.radio_group2);
        radioGroup2.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.radio_btn_enable2) {
                Toast.makeText(LandlockActivity.this, getString(R.string.msg_thread_enable_ll), Toast.LENGTH_SHORT).show();
            } else if (checkedId == R.id.radio_btn_disable2) {
                Toast.makeText(LandlockActivity.this, getString(R.string.msg_thread_disable_ll), Toast.LENGTH_SHORT).show();
            }
        });

        Button btn_landlock_file_in_new_thread = findViewById(R.id.btn_landlock_file_in_new_thread);
        btn_landlock_file_in_new_thread.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                LoadFileArgs();
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        int selectedId = radioGroup.getCheckedRadioButtonId();
                        boolean isEnableLandlock = selectedId == R.id.radio_btn_enable;

                        String message = getString(R.string.msg_new_thread_start);

                        if (landlock.isSupport()) {
                            message += getString(R.string.msg_landlock_supported);

                            if (isEnableLandlock) {
                                message += getString(R.string.msg_landlock_enabled);
                                message += setLandlockFileRules(landlock);
                            } else {
                                message += getString(R.string.msg_landlock_disabled);
                            }

                            if (!readfilename.isEmpty()) {
                                message += readFileContent(readfilename);
                            }

                            if (!writefilename.isEmpty()) {
                                String inputContent = et_input_content.getText().toString().trim();
                                if (!inputContent.isEmpty()) {
                                    try {
                                        FileUtils.writeStringToFilePath(writefilename, inputContent);
                                        message += getString(R.string.msg_written_to) + writefilename + "\n";
                                    } catch (IOException e) {
                                        message += getString(R.string.msg_write_failed) + e.toString() + "\n";
                                    }
                                }
                                message += readFileContent(writefilename);
                            }

                        } else {
                            message += getString(R.string.msg_landlock_not_supported);
                        }

                        String finalMessage = message;
                        btn_landlock_file_in_new_thread.post(new Runnable() {
                            @Override
                            public void run() {
                                text_output.setText(finalMessage);
                            }
                        });
                    }
                }).start();

            }
        });

        Button btn_landlock_web_in_new_thread = findViewById(R.id.btn_landlock_web_in_new_thread);
        btn_landlock_web_in_new_thread.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (!LoadLandLockNetArgs()) {
                    text_output.setText(getString(R.string.msg_net_config_failed));
                    return;
                }
                if (!LoadTestNetArgs()) {
                    text_output.setText(getString(R.string.msg_test_config_failed));
                    return;
                }
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        int selectedId = radioGroup2.getCheckedRadioButtonId();
                        boolean isEnableLandlock = selectedId == R.id.radio_btn_enable2;

                        String message = getString(R.string.msg_new_thread_start);

                        if (landlock.isSupport()) {
                            message += getString(R.string.msg_landlock_supported);

                            if (isEnableLandlock) {
                                message += getString(R.string.msg_landlock_enabled);
                                if (!landlock.isSupportNet()) {
                                    message += getString(R.string.msg_net_not_supported);
                                } else {
                                    message += getString(R.string.msg_net_supported);
                                    message += setLandlockNetRules(landlock);
                                }
                            } else {
                                message += getString(R.string.msg_landlock_disabled);
                            }

                            if (!listen_port_try.isEmpty()) {
                                message += getString(R.string.msg_try_listen_port) + listen_port_try + "\n";
                                message += listenOnPort(listen_port_try);
                            }

                            if (!connect_port_try.isEmpty()) {
                                message += getString(R.string.msg_try_connect) + connect_ip_try + getString(R.string.msg_port_label) + connect_port_try + "\n";
                                message += ConnectOnPort(connect_ip_try, connect_port_try);
                            }

                        } else {
                            message += getString(R.string.msg_landlock_not_supported);
                        }

                        String finalMessage = message;
                        btn_landlock_file_in_new_thread.post(new Runnable() {
                            @Override
                            public void run() {
                                text_output.setText(finalMessage);
                            }
                        });
                    }
                }).start();

            }
        });

        Button btn_landlock_file_in_main_thread = findViewById(R.id.btn_landlock_file_in_main_thread);
        btn_landlock_file_in_main_thread.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                LoadFileArgs();

                String message = getString(R.string.msg_main_thread_start);
                if (!readfilename.isEmpty()) {
                    message += readFileContent(readfilename);
                }
                if (!writefilename.isEmpty()) {
                    message += readFileContent(writefilename);
                }

                text_output.setText(message);
            }
        });

    }

    private static final int REQUEST_MEDIA_PERMISSIONS = 1001;

    private void requestStoragePermissions() {
        List<String> permissions = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_IMAGES)
                    != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.READ_MEDIA_IMAGES);
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_VIDEO)
                    != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.READ_MEDIA_VIDEO);
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_AUDIO)
                    != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.READ_MEDIA_AUDIO);
            }
        } else {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.READ_EXTERNAL_STORAGE);
            }
        }
        if (!permissions.isEmpty()) {
            ActivityCompat.requestPermissions(this,
                    permissions.toArray(new String[0]), REQUEST_MEDIA_PERMISSIONS);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                Log.w(TAG, "MANAGE_EXTERNAL_STORAGE not granted, redirecting to settings");
                Toast.makeText(this, getString(R.string.msg_need_all_files_access), Toast.LENGTH_LONG).show();
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQUEST_MEDIA_PERMISSIONS) {
            StringBuilder sb = new StringBuilder(getString(R.string.msg_perm_result));
            for (int i = 0; i < permissions.length; i++) {
                sb.append(permissions[i]).append(": ")
                        .append(grantResults[i] == PackageManager.PERMISSION_GRANTED ? getString(R.string.msg_perm_granted) : getString(R.string.msg_perm_denied))
                        .append("\n");
            }
            Log.d(TAG, sb.toString());
        }
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private String listenOnPort(String listen_port_try) {
        String message = "";
        ServerSocket serverSocket = null;
        Socket clientSocket = null;
        try {
            int port = Integer.parseInt(listen_port_try);

            serverSocket = new ServerSocket(port);
            serverSocket.setSoTimeout(listen_timeout);

            message += getString(R.string.msg_listen_success) + port + getString(R.string.msg_listen_waiting) + listen_timeout + getString(R.string.msg_listen_timeout_suffix);

            clientSocket = serverSocket.accept();
            message += getString(R.string.msg_client_connected) + clientSocket.getInetAddress() + ":" + clientSocket.getPort() + "\n";

            OutputStream out = clientSocket.getOutputStream();
            out.write("Hello, TCP client!\n".getBytes());
            out.flush();

            clientSocket.close();
            serverSocket.close();
            message += getString(R.string.msg_conn_closed);
        } catch (SocketTimeoutException e) {
            message += getString(R.string.msg_listen_timeout);
        } catch (SocketException e) {
            message += e.toString();
        } catch (IOException e) {
            message += e.toString();
        }finally {
            if (clientSocket != null) {
                try {
                    clientSocket.close();
                } catch (IOException ignore) {}
            }
            if (serverSocket != null) {
                try {
                    serverSocket.close();
                } catch (IOException ignore) {}
            }
        }
        return message;
    }

    private String ConnectOnPort(String ip, String connect_port_try) {
        String message = "";
        Socket socket = null;
        try {
            int port = Integer.parseInt(connect_port_try);

            socket = new Socket(ip, port);
            socket.setSoTimeout(connect_timeout);
            message += getString(R.string.msg_connect_success) + ip + ":" + port + "\n";

            OutputStream out = socket.getOutputStream();
            out.write("Hello from client!\n".getBytes());
            out.flush();

            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[1024];
            int len = in.read(buffer);
            if (len > 0) {
                message += getString(R.string.msg_received_data) + new String(buffer, 0, len) + "\n";
            }

            socket.close();

        } catch (Exception e) {
            message += getString(R.string.msg_connect_failed) + e.toString() + "\n";
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignore) {}
            }
        }
        return message;
    }
}
