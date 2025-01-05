package com.elf.call;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;
import com.elf.call.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {


    private ActivityMainBinding binding;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        loadCallLibrary();
    }

    private void loadCallLibrary() {
        ELFCallUtil.extractSoFromApk(this, Call.LIB_CALL);
        String path = ELFCallUtil.getCopyLibsPath(this,Call.LIB_CALL);
        System.load(path);
    }



    public void dobbyHookClick(View v) {
        if (v instanceof TextView) {
            ((TextView) v).setText(Call.doNativeName());
        }
    }

    public void createThread(View v) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                v.post(new Runnable() {
                    @Override
                    public void run() {
                        Log.d("song", "Native createThread id = " + Thread.currentThread().getId());
                    }
                });
            }
        }, "songpengfei-haha").start();
    }

    public void getPid(View v) {
        Toast.makeText(this, Process.myPid() + "", Toast.LENGTH_SHORT).show();
    }

    public void pltHook(View v) {
        Hook.init();
    }



}