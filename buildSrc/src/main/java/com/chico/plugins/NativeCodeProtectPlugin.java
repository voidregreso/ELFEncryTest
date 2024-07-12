package com.chico.plugins;

import org.gradle.api.Plugin;
import org.gradle.api.Project;

public class NativeCodeProtectPlugin implements Plugin<Project> {
    @Override
    public void apply(Project project) {
        project.getTasks().register("nativeCodeProtect", NativeCodeProtectTask.class);
    }
}
