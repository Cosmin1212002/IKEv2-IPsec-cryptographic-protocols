# Trace — MAKE-IKE-SIG-PKC-DHE 4M

## Test rulat

```text
TEST_2P_MAKE_IKE_SIG_PKC_DH_4M
```

Protocol testat:

```text
MAKE-IKE-SIG-PKC-DHE 4M
```

Acest test verifică execuția protocolului `MAKE-IKE-SIG-PKC-DHE 4M` între doi participanți onești: `ana` și `bob`.

Scopul testului este să confirme că protocolul:

* schimbă corect mesajele `INIT_A`, `INIT_B`, `AUTH_A` și `AUTH_B`;
* generează valori Diffie-Hellman efemere;
* derivă chei de sesiune comune;
* verifică autentificarea prin semnături digitale;
* ajunge în starea `ESTABLISHED`;
* permite transmiterea de date protejate după finalizarea handshake-ului.

---

## Configurație criptografică observată în trace

În mesajele `INIT_A` și `INIT_B`, participanții transmit configurația criptografică folosită:

```text
autSec: HMACSHA256[128]
encSec: AES/CTR/NoPadding[128]
dh: ECDH[256]
autPub: SHA256withECDSA[256]
pkcSig: SHA256withECDSA[0]
```

Aceasta arată că testul folosește:

* `ECDH P-256` pentru schimbul Diffie-Hellman;
* `SHA256withECDSA` pentru semnăturile digitale;
* `HMACSHA256` pentru autentificare internă;
* `AES/CTR-128` pentru protecția datelor.

---

## Etapele principale ale trace-ului

### 1. Ana inițiază protocolul

Trace-ul începe cu sesiunea Anei în starea:

```text
state START
```

Ana construiește mesajul `INIT_A`:

```text
[KeyEx: ana] build InitMsg to bob, new state INIT_SENT
[Comm] MsgHeader: { INIT_A from ana to bob sid 70673E5BF59E4C16 }
```

Mesajul `INIT_A` conține:

* nonce-ul Anei;
* cheia publică Diffie-Hellman a Anei;
* configurația criptografică propusă.

După trimiterea mesajului, Ana trece în starea:

```text
INIT_SENT
```

---

### 2. Bob răspunde cu `INIT_B`

Bob primește mesajul `INIT_A` în starea `START`:

```text
[KeyEx: bob] recv InitMsg in state START
```

Apoi construiește mesajul `INIT_B`:

```text
[KeyEx: bob] build InitMsg to ana, new state INIT_RCVD
[Comm] MsgHeader: { INIT_B from bob to ana sid 70673E5BF59E4C16 }
```

Mesajul `INIT_B` conține:

* nonce-ul lui Bob;
* cheia publică Diffie-Hellman a lui Bob;
* configurația criptografică folosită de Bob.

După această etapă, Ana și Bob au schimbat valorile necesare pentru calcularea secretului Diffie-Hellman.

---

### 3. Ana construiește mesajul `AUTH_A`

Ana primește `INIT_B` în starea `INIT_SENT`:

```text
[KeyEx: ana] recv InitMsg in state INIT_SENT
```

Apoi construiește mesajul `AUTH_A`:

```text
[KeyEx: ana] build AuthMsg to bob, new state AUTH_SENT
[Comm] MsgHeader: { AUTH_A from ana to bob sid 70673E5BF59E4C16 }
```

Mesajul `AUTH_A` este protejat prin câmpul `edata`.

În trace apar componentele:

```text
edata
data
IV
mac
```

Acest lucru arată că mesajul de autentificare nu este transmis în clar. El este protejat prin criptare autentificată.

În interiorul acestui mesaj sunt protejate:

* semnătura digitală a Anei;
* certificatul Anei;
* datele inițiale transmise către Bob.

---

### 4. Bob verifică autentificarea Anei

Bob primește `AUTH_A` în starea `INIT_RCVD`:

```text
[KeyEx: bob] recvAuth in state INIT_RCVD
```

Verificarea reușește:

```text
[KeyEx: bob] Successful verification of ana's authenticator (SIG)
Successful authentication: remote user is ana
```

Această etapă confirmă că:

* semnătura Anei este validă;
* certificatul Anei este acceptat;
* Bob autentifică participantul `ana`;
* mesajul `AUTH_A` a fost verificat corect.

Bob primește și datele inițiale transmise de Ana:

```text
[KeyEx: bob] Received early data: Hello, I'm Ana (the initiator)
```

---

### 5. Bob construiește mesajul `AUTH_B`

După verificarea Anei, Bob construiește mesajul `AUTH_B`:

```text
[KeyEx: bob] build AuthMsg to ana, new state INIT_RCVD
[Comm] MsgHeader: { AUTH_B from bob to ana sid 70673E5BF59E4C16 }
```

Bob finalizează partea lui de handshake:

```text
[KeyEx: bob] Responder: Auth handshake done, state ESTABLISHED. Success
```

Acest lucru înseamnă că Bob a acceptat sesiunea și consideră cheia stabilită cu Ana.

---

### 6. Ana verifică autentificarea lui Bob

Ana primește `AUTH_B` în starea `AUTH_SENT`:

```text
[KeyEx: ana] recvAuth in state AUTH_SENT
```

Verificarea autentificatorului lui Bob reușește:

```text
[KeyEx: ana] Successful verification of bob's authenticator (SIG)
Successful authentication: remote user is bob
```

Ana finalizează handshake-ul:

```text
[KeyEx: ana] Initiator: Auth handshake done, state ESTABLISHED. Success
```

Ana primește și datele inițiale transmise de Bob:

```text
[KeyEx: ana] Received early data: Hello, I'm Bob (the responder)
```

---

## Starea finală a sesiunilor

Trace-ul confirmă că ambele sesiuni au ajuns în starea `ESTABLISHED`:

```text
[Party: ana] 1 sessions
Session[0]: sid 70673E5BF59E4C16 from ana to bob state ESTABLISHED

[Party: bob] 1 sessions
Session[0]: sid 70673E5BF59E4C16 from bob to ana state ESTABLISHED
```

Acesta este rezultatul așteptat pentru un protocol executat corect.

---

## Testarea comunicației după handshake

După finalizarea schimbului de chei, sistemul devine pregătit pentru comunicație:

```text
>> System ready for communications <<
```

Ana trimite un mesaj de date către Bob:

```text
Party[ana]: sends message to bob
[Comm] MsgHeader: { DATA from ana to bob sid 70673E5BF59E4C16 }
```

Mesajul este protejat ca `AE_DATA`, ceea ce arată că datele sunt transmise criptat și autentificat.

Bob primește și acceptă mesajul:

```text
Party[bob]: rcvd message from ana (ana). Accepted
```

Apoi Bob trimite un mesaj către Ana:

```text
Party[bob]: sends message to ana
[Comm] MsgHeader: { DATA from bob to ana sid 70673E5BF59E4C16 }
```

Ana primește și acceptă mesajul:

```text
Party[ana]: rcvd message from bob (bob). Accepted
```

Această etapă confirmă că materialul criptografic derivat în timpul protocolului este folosit efectiv pentru protecția datelor.

---

## Concluzie

Trace-ul confirmă execuția corectă a protocolului `MAKE-IKE-SIG-PKC-DHE 4M`.

Rezultatele importante sunt:

* mesajele `INIT_A` și `INIT_B` sunt transmise corect;
* participanții schimbă nonce-uri și valori publice Diffie-Hellman;
* mesajele `AUTH_A` și `AUTH_B` sunt protejate prin criptare autentificată;
* Ana și Bob își verifică reciproc semnăturile digitale;
* ambii participanți ajung în starea `ESTABLISHED`;
* datele transmise după handshake sunt acceptate în ambele direcții.

Testul demonstrează că protocolul realizează autentificare mutuală prin `SIG-PKC`, stabilește chei de sesiune valide și permite comunicație securizată după finalizarea schimbului de chei.
