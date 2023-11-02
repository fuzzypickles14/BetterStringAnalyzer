plugins {
    id("java")
}

group = "com.BSF"
version = "0.1"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation(files("lib/icu4j-73_2.jar"))
    implementation(files("C:\\ReverseEngineering\\ghidra_10.3_PUBLIC\\Ghidra\\Features\\Base\\lib\\Base.jar",
            "C:\\ReverseEngineering\\ghidra_10.3_PUBLIC\\Ghidra\\Framework\\SoftwareModeling\\lib\\SoftwareModeling.jar",
            "C:\\ReverseEngineering\\ghidra_10.3_PUBLIC\\Ghidra\\Framework\\Utility\\lib\\Utility.jar",
            "C:\\ReverseEngineering\\ghidra_10.3_PUBLIC\\Ghidra\\Framework\\Generic\\lib\\Generic.jar",
            "C:\\ReverseEngineering\\ghidra_10.3_PUBLIC\\Ghidra\\Framework\\Project\\lib\\Project.jar",
            "C:\\ReverseEngineering\\ghidra_10.3_PUBLIC\\Ghidra\\Framework\\Docking\\lib\\Docking.jar",
            "C:\\ReverseEngineering\\ghidra_10.3_PUBLIC\\Ghidra\\Framework\\Gui\\lib\\Gui.jar"))
}

tasks.test {
    useJUnitPlatform()
}