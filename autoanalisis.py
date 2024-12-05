from colorama import Fore, Back, Style
from dotenv import load_dotenv
import colorama
import requests
import time
import os

load_dotenv()
colorama.init()

print("\033[H\033[J", end="")
print("En marcha!")

api_key = os.getenv('API_KEY')

url = "https://www.virustotal.com/api/v3/files"


headers = {
    "x-apikey": api_key,
}


downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
already_seen = set(os.listdir(downloads_folder))

while True:
    time.sleep(3)
    current_files = set(os.listdir(downloads_folder))
    new_files = current_files - already_seen

    if new_files:
        for file in new_files:

            if file.endswith('.tmp'):
                continue

            file_path = os.path.join(downloads_folder, file) 

            try:

                with open(file_path, 'rb') as f:

                    response = requests.post(url, headers=headers, files={'file': f})
                    

                if response.status_code == 200:
                    analysis_id = response.json()['data']['id']
                    status_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'


                    print("\033[H\033[J", end="")
                    print('Se ha encontrado un nuevo archivo para analizar:', file)
                    print('Esperando 10 segundos para el analisis')
                    time.sleep(15)
                    response = requests.get(status_url, headers=headers)
                    stats = response.json()['data']['attributes']['stats']
                    print("\033[H\033[J", end="")

                    #Respuesta de los analisis
                    print('--------------------------------------------------------------------------')
                    print(f'Escaneando el archivo: {Fore.BLUE}{file}{Style.RESET_ALL}')
                    print(f'Resultados del analisis: {Fore.RED}{stats}{Style.RESET_ALL}')
                    detected = stats['malicious'] + stats['suspicious'] +  stats['harmless'] + stats['timeout'] + stats['confirmed-timeout'] + stats['failure']
                    undetected = stats['undetected']
                    print(f'El resultado final es: {Fore.RED}{detected}{Fore.WHITE}/{Fore.GREEN}61 {Fore.WHITE}| {Fore.BLUE}{undetected} Okeys{Style.RESET_ALL}')
                    print('--------------------------------------------------------------------------')


                else:
                    print("Failed to upload file:", response.status_code, response.text)

            except Exception as e:
                print(f"Error uploading file {file}: {e}")

    already_seen = current_files


