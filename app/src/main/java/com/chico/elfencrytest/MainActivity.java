package com.chico.elfencrytest;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;

import com.chico.elfencrytest.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("elfencrytest");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        binding.sampleText.setText(getSectionTable());
    }

    public static native String getSectionTable();

}