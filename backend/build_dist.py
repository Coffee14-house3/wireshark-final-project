import os
import shutil
import zipfile

def create_dist_package():
    """
    Packages the Flask application into a dist.zip file for Tencent Cloud deployment.
    It automatically moves frontend HTML files into the 'templates' folder.
    """
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    frontend_dir = os.path.join(os.path.dirname(backend_dir), 'frontend')
    dist_dir = os.path.join(backend_dir, 'dist_temp')
    zip_filename = os.path.join(backend_dir, 'tencent_cloud_dist.zip')

    print("Starting build process...")

    # 1. Clean up old dist folder if it exists
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    os.makedirs(dist_dir)

    # 2. Create the 'templates' directory inside dist
    templates_dir = os.path.join(dist_dir, 'templates')
    os.makedirs(templates_dir)

    # 3. Copy all necessary backend files
    files_to_copy = [f for f in os.listdir(backend_dir) if f.endswith('.py') and f != 'build_dist.py']
    files_to_copy.extend(['requirements.txt', 'Dockerfile', '.dockerignore'])
    
    for file in files_to_copy:
        src = os.path.join(backend_dir, file)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(dist_dir, file))
            print(f"Copied backend file: {file}")

    # 4. Copy all HTML files from frontend to templates folder
    if os.path.exists(frontend_dir):
        for file in os.listdir(frontend_dir):
            if file.endswith('.html'):
                shutil.copy(os.path.join(frontend_dir, file), os.path.join(templates_dir, file))
                print(f"Copied template: {file}")

    # 5. Create the ZIP file
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(dist_dir):
            for file in files:
                file_path = os.path.join(root, file)
                zipf.write(file_path, os.path.relpath(file_path, dist_dir))

    print(f"\nSuccess! Your deployment package is ready: {zip_filename}")

if __name__ == '__main__':
    create_dist_package()