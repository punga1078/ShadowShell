import os

class ShellEmulator:
    def __init__(self):
        self.user = "root"
        self.hostname = "srv-finanzas-01" 
        self.cwd = "/root"
        
        # Sistema de archivos falso 
        self.file_system = {
            "/": ["bin", "boot", "dev", "etc", "home", "lib", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"],
            
            # --- Honeyfiles ---
            "/root": ["passwords.txt", "wallet_backup.json", "clientes_2025.csv", ".ssh"],
            "/root/.ssh": ["id_rsa", "authorized_keys"],
            "/home": ["guest"],
            
            # Carpetas del sistema
            "/bin": ["bash", "ls", "cp", "mv", "rm", "cat", "wget", "curl"], # Agregué wget y curl por si queremos simularlos luego
            "/etc": ["passwd", "shadow", "hostname", "network"],
            "/var": ["log", "www", "backups"],
            "/var/www": ["html"],
            "/var/www/html": ["index.html", "robots.txt"],
            "/tmp": ["sess_x890s7f89", "systemd-private-xyz"],
            
            # Carpetas vacías de Relleno
            "/usr": ["bin", "lib", "share"],
            "/usr/bin": [],
            "/sys": [],
            "/proc": [],
            "/dev": [],
            "/boot": [],
            "/lib": [],
            "/mnt": [],
            "/media": [],
            "/opt": [],
            "/run": [],
            "/sbin": [],
            "/srv": []
        }

        # --- CONTENIDO FALSO ---
        self.file_contents = {
            "passwords.txt": "admin:Admin123\nroot:P@ssw0rd2024\nfinance:MoneyMaker$!",
            "wallet_backup.json": '{"btc_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "private_key": "NO_COMPARTIR_CON_NADIE"}',
            "clientes_2025.csv": "ID,Nombre,Email,Tarjeta,Saldo\n1,Juan Perez,juan@gmail.com,4500-1234-5678,50000USD\n2,Maria Lopez,maria@hotmail.com,4111-2222-3333,120000USD",
            "shadow": "root:$6$hK...:18345:0:99999:7:::",
            "passwd": "root:x:0:0:root:/root:/bin/bash\nguest:x:1000:1000:Guest:/home/guest:/bin/bash",
            "robots.txt": "User-agent: *\nDisallow: /admin_panel"
        }
    def get_prompt(self):
        return f"{self.user}@{self.hostname}:{self.cwd}# "

    def execute(self, cmd_line):
        if not cmd_line.strip():
            return ""
            
        parts = cmd_line.strip().split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # Router de comandos
        if command == "cd":
            return self._cd(args)
        elif command == "ls":
            return self._ls(args)
        elif command == "pwd":
            return self._pwd()
        elif command == "whoami":
            return f"{self.user}\r\n"
        elif command == "help":
            return "GNU bash, version 5.1.16(1)-release\r\nCommands: cd, ls, pwd, whoami, exit\r\n"
        elif command == "cat":
            return self._cat(args)
        elif command == "wget":
            return self._wget(args)
        elif command == "curl":
            return self._curl(args)
        else:
            return f"bash: {command}: command not found\r\n"

    # --- Métodos internos (deben estar alineados con los de arriba) ---

    def _pwd(self):
        return f"{self.cwd}\r\n"
    
    def _wget(self, args):
        if not args:
            return "wget: missing URL\r\n"
        
        url = args[0]
        # Logica simple para sacar nombre del archivo, si no hay, usa index.html
        filename = url.split("/")[-1] 
        if not filename: 
            filename = "index.html"

        # --- Agregamos el archivo al sistema de archivos falso ---
        if self.cwd in self.file_system and filename not in self.file_system[self.cwd]:
            self.file_system[self.cwd].append(filename)
            
            if filename not in self.file_contents:
                self.file_contents[filename] = f"# FAKE_CONTENT from {url}\nThis is a honeypot artifact."
                domain = url.split('//')[-1].split('/')[0]
                output = [
                    f"--2025-12-23 10:00:01--  {url}",
                    f"Resolving {domain}... 192.168.1.55",
                    f"Connecting to {domain}... connected.",
                    "HTTP request sent, awaiting response... 200 OK",
                    "Length: 10240 (10K) [application/octet-stream]",
                    f"Saving to: '{filename}'",
                    "",
                    f"{filename} 100%[===================>] 10.00K --.-KB/s in 0.001s",
                    "",
                    f"2025-12-23 10:00:02 ({filename}) - saved [10240/10240]",
                    "\r\n"
                ]
                return "\r\n".join(output)

    
    def _curl(self,args):
        if not args:
            return "curl: try 'curl --help' for more information\r\n"
        return f"<!DOCTYPE html>\r\n<html><head><title>Hacked</title></head><body>Malware Loaded</body></html>\r\n"

    def _ls(self, args):
        # 1. Detectar banderas y rutas
        show_hidden = False
        long_format = False
        path = self.cwd # Por defecto, listamos donde estamos

        # Separamos los argumentos que son banderas (empiezan con -) de las rutas
        clean_args = []
        for arg in args:
            if arg.startswith("-"):
                if "a" in arg: show_hidden = True
                if "l" in arg: long_format = True
            else:
                clean_args.append(arg)

        # Si el usuario especificó una carpeta (ej: ls /etc), la usamos
        if clean_args:
            path = self._resolve_path(clean_args[0])

        # 2. Obtener archivos
        if path in self.file_system:
            items = self.file_system[path]
            
            # Si no pidió ocultos (-a), filtramos los que empiezan con punto
            if not show_hidden:
                items = [i for i in items if not i.startswith(".")]
            
            # Agregamos . y .. si es -a
            if show_hidden:
                items = [".", ".."] + items

            # 3. Formato de salida
            if long_format:
                return self._generate_fake_details(items)
            else:
                return "  ".join(items) + "\r\n"
        else:
            path_err = clean_args[0] if clean_args else path
            return f"ls: cannot access '{path_err}': No such file or directory\r\n"

    def _generate_fake_details(self, items):
        # Generamos una lista falsa que parece real (drwxr-xr-x root root ...)
        output = "total 64\r\n"
        import random
        from datetime import datetime
        
        # Fecha falsa (hoy)
        date_str = datetime.now().strftime("%b %d %H:%M")

        for item in items:
            # Es directorio si no tiene punto (regla simple para este honeypot)
            is_dir = "." not in item 
            perms = "drwxr-xr-x" if is_dir else "-rw-r--r--"
            links = "2" if is_dir else "1"
            size = random.randint(64, 4096)
            
            # Fila tipo Linux: perms links user group size date name
            line = f"{perms} {links} root root {size:5} {date_str} {item}\r\n"
            output += line
            
        return output

    def _cd(self, args):
        if not args:
            self.cwd = "/root"
            return ""
        
        target = args[0]
        new_path = self._resolve_path(target)

        if new_path in self.file_system:
            self.cwd = new_path
            return ""
        else:
            return f"bash: cd: {target}: No such file or directory\r\n"

    def _cat(self, args):
        if not args:
            return ""
        filename = args[0]
        
        if filename in self.file_contents:
            return self.file_contents[filename] + "\r\n"
            
        elif self.cwd in self.file_system and filename in self.file_system[self.cwd]:
             return "" 
             
        else:
            return f"cat: {filename}: No such file or directory\r\n"

    def _resolve_path(self, path):
        # Manejo de rutas absolutas
        if path == "/":
            return "/"
        
        if path.startswith("/"):
            return path.rstrip("/") 
            
        # Manejo de rutas relativas
        if path == "..":
            if self.cwd == "/": return "/"
            return os.path.dirname(self.cwd)
        
        if path == ".":
            return self.cwd

        # Unir directorio actual + nuevo
        return os.path.join(self.cwd, path).replace("\\", "/")