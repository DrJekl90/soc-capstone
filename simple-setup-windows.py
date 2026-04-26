#!/usr/bin/env python3
"""
SOC Capstone - Simple Windows Setup Script
Run this inside your 'soc-capstone' folder
"""

import os
import shutil

def main():
    print("🚀 SOC Capstone Simple Setup (Windows)")
    print("=" * 45)
    
    current = os.getcwd()
    print(f"Current folder: {current}")
    
    # Check if we're inside soc-capstone
    if not os.path.exists("README.md"):
        print("\n❌ ERROR: Please run this script INSIDE the 'soc-capstone' folder!")
        print("   cd C:\\Users\\dakil\\Downloads\\soc-capstone")
        return
    
    # Paths to logo and banner
    logo_src = os.path.join("..", "soc-capstone-final", "logo.png")
    banner_src = os.path.join("..", "soc-capstone-final", "banner.png")
    
    # Copy logo
    if os.path.exists(logo_src):
        shutil.copy(logo_src, "logo.png")
        print("✅ Logo copied successfully")
    else:
        print("⚠️  Logo not found. Please copy it manually from soc-capstone-final folder.")
    
    # Copy banner
    if os.path.exists(banner_src):
        shutil.copy(banner_src, "banner.png")
        print("✅ Banner copied successfully")
    else:
        print("⚠️  Banner not found. Please copy it manually.")
    
    print("\n" + "=" * 45)
    print("✅ Setup complete!")
    print("\nNow run these commands in Command Prompt:")
    print("  git init")
    print("  git add .")
    print("  git commit -m \"Initial commit - SOC Capstone\"")
    print("  git remote add origin https://github.com/DrJekl90/soc-capstone.git")
    print("  git push -u origin main")
    print("\nYour repository is ready!")

if __name__ == "__main__":
    main()
