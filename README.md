# PosteID seed extractor

Poste Italiane è uno dei fornitori SPID, il sistema di identità digitale italiano. Opera con il marchio PosteID, per effettuare l'accesso è necessario avere installato l'applicazione ufficiale delle Poste.

I difetti dell'applicazione sono:
- occupa molto spazio nel telefono
- non puoi avere più di un utente per ogni telefono
- ci mette molto ad avviarsi

Con questo strumento è possibile generare un qr code che ti permette di utilizzare un'app di OTP per custodire i tuoi seed OTP.

## Come si usa?

Questo tool è scritto in Python, per questo motivo devi installarlo prima prima di procedere.

Successivamente hai bisogno di installare le dipendenze, puoi usare il comando:
```bash
pip install -r requirements.txt
```

Poi puoi avviare il tool digitando:
```bash
python extractor.py extract
```

### Utilizzo avanzato

Sono disponibili anche altri comandi

```
usage: extractor.py [-h] {extract,generate_qr,generate_code} ...

This is a tool to extract the OTP seed of PosteID app

optional arguments:
  -h, --help            show this help message and exit

option:
  Action to be performed

  {extract,generate_qr,generate_code}
    extract             Extract OTP code
    generate_qr         Generate importable qr code
    generate_code       Generate OTP code of a specific time
```

```
usage: extractor.py extract [-h] [-o] [-s]

optional arguments:
  -h, --help         show this help message and exit
  -o, --only-output  Only show the output on the screen (do not write output in the secret.txt file)
  -s, --show-string  Print OTP seed as string instead of qr code
```

```
usage: extractor.py generate_qr [-h] [-s SEED]

optional arguments:
  -h, --help            show this help message and exit
  -s SEED, --seed SEED  The OTP seed
```

```
usage: extractor.py generate_code [-h] [-s SEED] [-t TIME]

optional arguments:
  -h, --help            show this help message and exit
  -s SEED, --seed SEED  The OTP seed
  -t TIME, --time TIME  Generate OTP in a precise time (UnixEpoch time), default is now
```

## Problemi noti

Se stai utilizzando questo tool ed è da molto tempo che non install l'app PosteID potrebbe capitarti un errore. Per risovere procedi in questo modo:
- Installa PosteID in un telefono
- Effetua l'accesso
- L'app ti farà impostare un pin
- Estrai l'OTP seed con questo tool
- Se vuoi, disintalla PosteID

## No disco!

Per impostazione predefinita questo tool salva una copia del tuo seed OTP nel file secret.txt. Se non vuoi esegui il comando `extract` con il parametro `--only-output`.

## Quale applicazione installo?

Probabilmente non vorrai andare utilizzare sempre il tuo computer per generare i codici OTP, per questo motivo spesso si utilizzano delle applicazioni apposite da installare nel telefono.

Purtroppo non tutte sono compatibili, ho raccolto le principali.

| App | Android | iOS | Note |
|:---:|:-------:|:---:|:------:|
| Auty | ❌ | ❌ | Non supporta i codici di 120 secondi |
| Google Authenticator | ❌ | ✅ |  Non supporta i codici di 120 secondi |
| LastPass | ✅ | ✅ | |
| Yubico | ✅ | | |
| Aegis | ✅ | ✅ | Testato anche da me |

Fonte: [Laban Sköllermark](https://labanskoller.se/blog/2019/07/11/many-common-mobile-authenticator-apps-accept-qr-codes-for-modes-they-dont-support/)

## Responsabilità

Questo software viene fornito senza garanzie. Non sono responsabile per evetuali danni che potrebbe causare. Effettua sempre un backup di tutte le informazioni che potresti perdere.

Questo programma è stato creato a scopo didattico.


