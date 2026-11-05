#!/usr/bin/env python3
"""Generate a JSON-format iOSRAT.xcodeproj for Xcode 26.
pbxproj is a JSON plist; Xcode 26 uses the PBXFileReference (objectVersion 50) model,
not the newer file-set (objectVersion 56) model."""
import json, os, secrets

def _id():
    return secrets.token_hex(16).upper()

P_PROJ   = _id()
P_FAPP   = _id()
P_FVC    = _id()
P_FCONST = _id()
P_FINFO  = _id()
P_PRODBUNDLE = _id()
P_GROUP  = _id()
P_PRODUCTS = _id()
P_TOP    = _id()
P_BAPP   = _id()
P_BVC    = _id()
P_BCONST = _id()
P_SRCPHASE = _id()
P_FRWPHASE = _id()
P_RESPPHASE = _id()
P_TARGET = _id()
P_PROJCFG = _id()
P_TGTCFG = _id()
P_PDBG   = _id()
P_PDRE   = _id()
P_TDBG   = _id()
P_TDRE   = _id()

APP_NAME = "iOSRAT"
BUNDLE_ID = "com.xag.iosrat"

def cfg(name, team=""):
    base = {
        "ALWAYS_SEARCH_USER_PATHS": "NO",
        "CLANG_C_LANGUAGE_STANDARD": "gnu17",
        "CLANG_CXX_LANGUAGE_STANDARD": "gnu17",
        "COPY_PHASE_STRIP": "NO",
        "ENABLE_TESTABILITY": "YES",
        "GCC_C_LANGUAGE_STANDARD": "gnu17",
        "GCC_OPTIMIZATION_LEVEL": "0",
        "MARKETING_VERSION": "1.0",
        "INFOPLIST_FILE": f"{APP_NAME}/Info.plist",
        "PRODUCT_BUNDLE_IDENTIFIER": BUNDLE_ID,
        "PRODUCT_NAME": "$(TARGET_NAME)",
        "SWIFT_COMPILATION_MODE": "wholesodule",
        "SWIFT_OPTIMIZATION_LEVEL": "",
        "SWIFT_VERSION": "5.0",
        "TARGETED_DEVICE_FAMILY": "1,2",
    }
    if name == "Debug":
        base.update({"ENABLE_USER_SCRIPT_SANDBOXING": "YES",
                     "CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES": "YES",
                     "IPHONEOS_DEPLOYMENT_TARGET": "16.0"})
    else:
        base.update({"IPHONEOS_DEPLOYMENT_TARGET": "16.0"})
    if name == "Debug" and team:
        base["DEVELOPMENT_TEAM"] = team
    return {"isa": "XCBuildConfiguration", "buildSettings": base,
            "name": name}

objects = {
    P_PROJ: {"isa": "PBXProject",
             "buildConfigurationList": P_PROJCFG,
             "compatibilityVersion": "Xcode 14.0",
             "developmentRegion": "en",
             "hasScannedForEncodings": 0,
             "knownRegions": ["en", "Base"],
             "mainGroup": P_TOP,
             "productBundleIdentifier": BUNDLE_ID,
             "target": P_TARGET},
    P_FAPP: {"isa": "PBXFileReference", "lastKnownFileType": "sourcecode.swift",
             "name": "AppDelegate.swift", "path": f"{APP_NAME}/AppDelegate.swift",
             "sourceTree": "<group>"},
    P_FVC: {"isa": "PBXFileReference", "lastKnownFileType": "sourcecode.swift",
            "name": "ViewController.swift", "path": f"{APP_NAME}/ViewController.swift",
            "sourceTree": "<group>"},
    P_FCONST: {"isa": "PBXFileReference", "lastKnownFileType": "sourcecode.swift",
               "name": "Constants.swift", "path": f"{APP_NAME}/Constants.swift",
               "sourceTree": "<group>"},
    P_FINFO: {"isa": "PBXFileReference", "lastKnownFileType": "text.plist.xml",
              "name": "Info.plist", "path": f"{APP_NAME}/Info.plist",
              "sourceTree": "<group>"},
    P_PRODBUNDLE: {"isa": "PBXFileReference", "lastKnownFileType": "wrapper.application",
                   "name": APP_NAME, "path": APP_NAME, "sourceTree": "<group>"},
    P_GROUP: {"isa": "PBXGroup",
              "children": [P_FAPP, P_FVC, P_FCONST, P_FINFO],
              "path": APP_NAME, "sourceTree": "<group>"},
    P_PRODUCTS: {"isa": "PBXGroup", "children": [P_PRODBUNDLE],
                 "name": "Products", "sourceTree": "<group>"},
    P_TOP: {"isa": "PBXGroup", "children": [P_GROUP, P_PRODUCTS], "sourceTree": "<group>"},
    P_BAPP: {"isa": "PBXBuildFile", "fileRef": P_FAPP},
    P_BVC: {"isa": "PBXBuildFile", "fileRef": P_FVC},
    P_BCONST: {"isa": "PBXBuildFile", "fileRef": P_FCONST},
    P_SRCPHASE: {"isa": "PBXSourcesBuildPhase",
                 "files": [P_BAPP, P_BVC, P_BCONST], "runOnlyForDeploymentPostprocessing": 0},
    P_RESPPHASE: {"isa": "PBXResourcesBuildPhase",
                  "files": [], "runOnlyForDeploymentPostprocessing": 0},
    P_FRWPHASE: {"isa": "PBXFrameworksBuildPhase",
                 "files": [], "runOnlyForDeploymentPostprocessing": 0},
    P_TARGET: {"isa": "PBXNativeTarget",
               "buildConfigurationList": P_TGTCFG,
               "buildPhases": [P_SRCPHASE, P_FRWPHASE, P_RESPPHASE],
               "name": APP_NAME, "productReference": P_PRODBUNDLE,
               "productType": "com.apple.producttype.application"},
    P_PROJCFG: {"isa": "XCConfigurationList",
                "buildConfigurationList": [P_PDBG, P_PDRE],
                "defaultConfigurationIsVisible": 0},
    P_TGTCFG: {"isa": "XCConfigurationList",
               "buildConfigurationList": [P_TDBG, P_TDRE],
               "defaultConfigurationIsVisible": 0},
    P_PDBG: cfg("Debug"),
    P_PDRE: cfg("Release"),
    P_TDBG: cfg("Debug", team=""),
    P_TDRE: cfg("Release", team=""),
}

proj = {
    "archiveVersion": "1",
    "classes": {},
    "objectVersion": "50",
    "objects": objects,
    "rootObject": P_PROJ,
}

os.makedirs(f"{APP_NAME}.xcodeproj", exist_ok=True)
out = f"{APP_NAME}.xcodeproj/project.pbxproj"
with open(out, "w") as f:
    json.dump(proj, f, indent=2, sort_keys=True)
    f.write("\n")
print("wrote", out)
