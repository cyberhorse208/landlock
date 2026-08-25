package com.vivo.landlocktest;

import android.os.Bundle;
import android.view.MenuItem;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;

public class SettingsActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setTitle(getString(R.string.title_settings));
            actionBar.setDisplayHomeAsUpEnabled(true);
        }

        RadioGroup radioGroupImpl = findViewById(R.id.radio_group_impl);
        RadioButton radioBtnImplReflect = findViewById(R.id.radio_btn_impl_reflect);
        TextView tvReflectStatus = findViewById(R.id.tv_reflect_status);

        boolean reflectAvailable = new ReflectLandlock().isAvailable();
        radioBtnImplReflect.setEnabled(reflectAvailable);

        boolean useReflect = LandlockPrefs.isUseReflect(this) && reflectAvailable;
        if (!reflectAvailable && LandlockPrefs.isUseReflect(this)) {
            // Previously chosen reflect impl, but it's no longer available:
            // fall back to native impl and persist this.
            LandlockPrefs.setUseReflect(this, false);
        }
        radioGroupImpl.check(useReflect ? R.id.radio_btn_impl_reflect : R.id.radio_btn_impl_native);

        updateReflectStatus(tvReflectStatus, reflectAvailable);

        radioGroupImpl.setOnCheckedChangeListener((group, checkedId) -> {
            boolean toReflect = checkedId == R.id.radio_btn_impl_reflect;
            LandlockPrefs.setUseReflect(this, toReflect);
            String msg = toReflect ? getString(R.string.msg_impl_switched_reflect)
                    : getString(R.string.msg_impl_switched_native);
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
            updateReflectStatus(tvReflectStatus, reflectAvailable);
        });
    }

    private void updateReflectStatus(TextView tvReflectStatus, boolean reflectAvailable) {
        String status = reflectAvailable
                ? getString(R.string.msg_reflect_available)
                : getString(R.string.msg_reflect_unavailable);
        tvReflectStatus.setText(status);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
