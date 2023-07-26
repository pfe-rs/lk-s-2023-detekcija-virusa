# 18.07.2023.
- Zavrsen UML sandbox
- U toku pravljenje dataset-a (virus log-ovi)
- Zavrsena podesavanja okruzenja za bezbedan rad sa virusima (automatsko pravljenje snapshot-ova, namesten UML rootfs, itd)
- Rad na filtriranju malvera sa MalwareBazaar sajta.

# 19.07.2023.
- Osposobljen Docker za brzi sandbox u kontejneru koji pruza i pristup internetu. Ispostavilo se da dosta virusa trazi pristup internetu, pa u UML-u nisu hteli
da rade kako treba.
- Uradjena Nautilus ekstenzija koja dodaje opciju "Scan for malware" u meni desnog klika.
- Nadjen i skinut dataset od oko 400 malvera koji rade na Linux-u na x86-64 procesorima.
- Uradjen strace za malvere u dataset-u koristeci Docker sandbox.
- Zapoceto pravljenje statistike redosleda sistemskih poziva u zavisnosti od toga da li je fajl maliciozan ili ne (matrica).

# 20.07.2023.
- Odlazak na bazen
- Napravljena C++ biblioteka za optimizaciju citanja velikog broja log fajlova iz Python-a. Biblioteka dinamicki povezana sa Python kodom.
- Zavrsena vizuelizacija redosleda sistemskih poziva (matrica). Napravljeno vise matrica za razlicite opsege broja sistemskih poziva. Bez korisnih rezultata za vadjenje
karakteristika za ML model.
- Napravljen filter za brisanje log-ova virusa koji nisu uspeli da se pokrenu pravilno.
- Napravljen log za normalne programe koristeci strace na host-u.
- Utvrdjeno da je dataset los zato sto dosta virusa nisu na kraju uspeli da urade nista maliciozno i svi su bili konzolni, dok su od normalnih programa vecina
bili graficki jer konzolne aplikacije cesto zatevaju user input, pa ih je tesko dinamicki testirati brzo. Uz sve to, ukupan broj programa u celom dataset-u je
relativno mali.

# 21.07.2023.
- Po preporuci uradjeno par histograma koji predstavljaju broj sistemskih poziva ili normalizovan broj sistemskih programa za razlicite programe iz dataset-a.
Histogrami su veoma slicni, tako da ponovo nije bilo korisnih karakteristika za ML model.
- Zapoceto istrazivanje Word2Vec-a i LSTM mreza za analizu teksta log-ova, po uzoru na rad o Neurlux mrezi
- Napravljena prezentacija za kraj dana

# 22.07.2023.
- Napravljen sandbox za Windows viruse koristeci Wine, Flatpak i Bottles.
- Ugradjena mogucnost za analizu Windows aplikacija u Nautilus ekstenziju.
- Wine podesen da radi sa Microsoft .NET Framework implementacijom
- Testirano par programa i prikupljeni njihovi log-ovi

# 23.07.2023.
- Izlet do manastira Tronosa.
- Uvece ukljuceno skeniranje Windows virusa za prikupljanje log-ova

# 24.07.2023.
- Utvrdjeno da se virusi unutar Bottles-a ne gase nakon sto se ugasi program za pracenje
- Log-ovi koji su postojali su greskom sacuvani na mestu pristupacnom iz sandbox-a, pa ih je neki ransomware enkriptovao.
- Zapocet rad na C programu koji bi trebalo da dodatnim namespace-ovima odvoji sandbox od host-a, postavi ogranicenja za upotrebu resursa i ubije ceo sandbox
kada se analiza zavrsi. Koriscenjem kontrol grupa, trebalo bi i da pruzi uvid u upotrebe resursa od strane programa u sandbox-u.
- Procitani celi dokumenti "The Linux Kernel documentation: IDmappings", capabilities(7), user_namespaces(7) i drugi relevantni dokumenti i izvucene beleske
za potrebe programa
- Podesena Azure virtuelna masina za treniranje LSTM mreze

# 25.07.2023.
- Zavrsen program za dodavanje user namespace-ova i kontrol grupa Flatpak sandbox-u. Ceka se testiranje.
- Iskucan kod za dotreniravanje Word2Vec mreze koristeci GloVe mapiranja kao pretrenirani model
- Zavrsen program za tokenizaciju log-ova za potrebe Word2Vec mreze. Umesto putanja, koriste se SELinux konteksti tih fajlova ili njihovih roditeljskih direktorijuma
- Dodata jos jedna C funkcija za obradu stringa u C++ biblioteku za optimizaciju citanja velikog broja fajlova. Posto je vecina koda pisana u C stilu i jedini C++
deo je bio pojavljivanje std::string klase, cela biblioteka je prevedena u C da bi se lakse povezivala sa Python-om kroz ctypes modul.
- Pusteno treniranje Word2Vec modela; kompjuter podesen da kompresuje memoriju kako bi sve moglo da stane u RAM

# 26.07.2023.
- Word2Vec treniranje ipak nije zavrseno, OOM killer je odlucio da ubije Python.
- Gensim biblioteka koja se koristi nema podrsku za treniranje na GPU posto je valjda arhitektura Word2Vec mreze takva da se dosta operacija mora raditi
sekvencijalno, pa velika paralelizacija na GPU procesoru ne bi pomogla mnogo. Iz tog razloga ne radim na Azure masini posto ona primarno ima dobar GPU procesor.
Da ne bih trosio vreme na dalje podesavanje mog laptopa da ovo uradi, prebacujem se na Google Colab.
- Ispisan ovaj dnevnik po secanju na prethodne dane izmedju danas i 19.07. Izvinjavam se na kasnjenju sa dnevnikom.

# Napomena
Ovaj dnevnik je pisan naknadno. Moguce je da neke stvari nisu dosledne ili nedostaju.
