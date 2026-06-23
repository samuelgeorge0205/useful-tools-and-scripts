from netmiko import ConnectHandler
from datetime import datetime
import os

# Directory paths
TEMPLATES_DIR = "templates"
GENERATED_DIR = "generated"
LOGS_DIR = "logs"
BACKUPS_DIR = "backups"

# Ensure directories exist
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(GENERATED_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(BACKUPS_DIR, exist_ok=True)

def log_message(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(os.path.join(LOGS_DIR, "router_config.log"), "a") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")
    print(message)

def generate_config(template_filename, output_filename, replacements):
    if not os.path.exists(template_filename):
        log_message(f"Template file {template_filename} not found.")
        return None

    with open(template_filename, 'r') as template_file:
        template_content = template_file.read()

    for placeholder, value in replacements.items():
        template_content = template_content.replace(placeholder, value)

    with open(output_filename, 'w') as output_file:
        output_file.write(template_content)

    log_message(f"Generated configuration saved to {output_filename}")
    return output_filename

def preview_config(config_file):
    if not os.path.exists(config_file):
        log_message(f"Config file {config_file} not found.")
        return

    print("\n==== CONFIGURATION PREVIEW ====")
    with open(config_file, "r") as f:
        print(f.read())
    print("================================\n")

def backup_config(device, filename_prefix, use_enable=False):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = os.path.join(BACKUPS_DIR, f"{filename_prefix}_backup_{timestamp}.txt")

    connection = ConnectHandler(**device)

    if use_enable:
        connection.enable()

    running_config = connection.send_command("show running-config")

    with open(backup_filename, "w") as f:
        f.write(running_config)

    log_message(f"Backup saved to {backup_filename}")
    connection.disconnect()

def send_config(device, config_file, use_enable=False):
    if not config_file or not os.path.exists(config_file):
        log_message(f"Config file {config_file} not found.")
        return

    with open(config_file, "r") as f:
        config_lines = f.read().splitlines()

    connection = ConnectHandler(**device)

    if use_enable:
        connection.enable()

    log_message(f"Sending config to {device['host']}...")
    output = connection.send_config_set(config_lines)
    log_message(output)

    log_message("Verifying configuration...")
    verify_output = connection.send_command("show running-config | section <VERIFY_SECTION>")
    verify_output += "\n" + connection.send_command("show running-config | include <VERIFY_PATTERN>")
    log_message(verify_output)

    connection.save_config()
    connection.disconnect()

    log_message("Configuration saved and session closed.")

def main():
    master_router_ip = input("Enter the Master Router IP (<MASTER_IP>): ")
    subnet_prefix = input("Enter subnet prefix (e.g., <a.b.c>): ")
    store_type = input("Enter the environment/type (<TYPE>): ")

    # Placeholder BGP router list (replace with real ones if needed)
    bgp_routers = [
        "<BGP_ROUTER_1>",
        "<BGP_ROUTER_2>",
        "<BGP_ROUTER_3>"
    ]

    print("Select one of the following BGP routers:")
    for i, router_ip in enumerate(bgp_routers, 1):
        print(f"{i}. {router_ip}")

    try:
        selected_index = int(input("Enter number: ")) - 1
        selected_router_ip = bgp_routers[selected_index]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    # Generic device credentials with placeholders
    master_router = {
        "device_type": "<DEVICE_TYPE>",          # e.g., cisco_ios
        "host": master_router_ip,
        "username": "<USERNAME>",
        "password": "<PASSWORD>",
        "secret": "<ENABLE_SECRET>"
    }

    bgp_router = {
        "device_type": "<DEVICE_TYPE>",
        "host": selected_router_ip,
        "username": "<USERNAME>",
        "password": "<PASSWORD>",
        "secret": "<ENABLE_SECRET>"
    }

    # Generate configs
    master_config_file = generate_config(
        os.path.join(TEMPLATES_DIR, f"master_template_{store_type}.txt"),
        os.path.join(GENERATED_DIR, f"generated_master_{store_type}.txt"),
        {"<a.b.c>": subnet_prefix}
    )

    bgp_config_file = generate_config(
        os.path.join(TEMPLATES_DIR, f"{selected_router_ip}_{store_type}.txt"),
        os.path.join(GENERATED_DIR, f"generated_{selected_router_ip}_{store_type}.txt"),
        {
            "<MASTER_IP>": master_router_ip,
            "<a.b.c>": subnet_prefix
        }
    )

    # Preview & confirm
    print("\n== MASTER ROUTER CONFIGURATION ==")
    preview_config(master_config_file)

    if input("Push master config? (yes/no): ").strip().lower() == "yes":
        backup_config(master_router, "master_router", use_enable=True)
        send_config(master_router, master_config_file, use_enable=True)
    else:
        log_message("Master router deployment skipped.")

    print("\n== BGP ROUTER CONFIGURATION ==")
    preview_config(bgp_config_file)

    if input(f"Push BGP config for {selected_router_ip}? (yes/no): ").strip().lower() == "yes":
        backup_config(bgp_router, f"bgp_router_{selected_router_ip}")
        send_config(bgp_router, bgp_config_file)
    else:
        log_message("BGP router deployment skipped.")

if __name__ == "__main__":
    main()
