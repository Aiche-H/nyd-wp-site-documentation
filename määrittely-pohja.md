# NYD Dokumentaatio

| fi | en |
|---|---|
| **[Katso](./README.md)** | **[See](./eng-documentation/en-README.md)** |

## Sisällysluettelo

**[1. Johdanto](#1-johdanto)**

* [1.1 Tarkoitus ja laajuus](#11-tarkoitus-ja-laajuus)
* [1.2 Tuote ja sen toimintaympäristö](#12-tuote-ja-sen-toimintaympäristö)
* [1.3 Määritelmät](#13-määritelmät)

**[2. Vaatimukset](#2-vaatimukset)**

* [2.1 Toiminnalliset vaatimukset](#21-toiminnalliset-vaatimukset)
  * [2.1.1 Käyttäjävaatimukset](#211-käyttäjävaatimukset)
  * [2.1.2 Järjestelmävaatimukset](#212-järjestelmävaatimukset)
* [2.2 Ei-toiminnalliset vaatimukset](#22-ei-toiminnalliset-vaatimukset)
  * [2.2.1 Suorituskykyvaatimukset](#221-suorituskykyvaatimukset)
  * [2.2.2 Turvallisuusvaatimukset](#222-turvallisuusvaatimukset)

**[3. Yleiskuvaus](#3-yleiskuvaus)**

* [3.1 Järjestelmän arkkitehtuuri](#31-järjestelmän-arkkitehtuuri)
* [3.2 Käyttäjät ja roolit](#32-käyttäjät-ja-roolit)
* [3.3 Käyttötapaukset](#33-käyttötapaukset)

**[4. Tiedot ja tietokanta](#4-tiedot-ja-tietokanta)**

* [4.1 Tietosisältö](#41-tietosisältö)
* [4.2 Käyttöintensiteetti](#42-käyttöintensiteetti)
* [4.3 Kapasiteettivaatimukset](#43-kapasiteettivaatimukset)
* [4.4 Tiedosto- ja asetustiedostot](#44-tiedosto--ja-asetustiedostot)

**[5. Arkkitehtuuri](#5-arkkitehtuuri)**

* [5.1 Looginen arkkitehtuuri](#51-looginen-arkkitehtuuri)
* [5.2 Tekninen arkkitehtuuri](#52-tekninen-arkkitehtuuri)

**[6. Käyttäjät](#6-käyttäjät)**

* [6.1 Käyttäjäluettelo](#61-käyttäjäluettelo)
* [6.2 Internetin käyttäjät](#62-internetin-käyttäjät)

**[7. Käyttötapaukset ja käyttöliittymä](#7-käyttötapaukset-ja-käyttöliittymä)**

* [7.1 Käyttötapaukset](#71-käyttötapaukset)
* [7.2 Käyttöliittymien yleiskuvaus](#72-käyttöliittymien-yleiskuvaus)
* [7.3 Toiminnot](#73-toiminnot)
  * [7.3.1 Toiminto 1](#731-toiminto-1)

**[8. Ulkoiset liittymät](#8-ulkoiset-liittymät)**

* [8.1 Laitteistoliittymä](#81-laitteistoliittymä)
* [8.2 Ohjelmistoliittymät](#82-ohjelmistoliittymät)
* [8.3 Tietoliikenneliittymät](#83-tietoliikenneliittymät)

**[9. Muut ominaisuudet](#9-muut-ominaisuudet)**

* [9.1 Suorituskyky ja vasteajat](#91-suorituskyky-ja-vasteajat)
* [9.2 Käytettävyys, toipuminen, turvallisuus, suojaukset](#92-käytettävyys-toipuminen-turvallisuus-suojaukset)
* [9.3 Siirrettävyys ja yhteensopivuus](#93-siirrettävyys-ja-yhteensopivuus)
* [9.4 Operoitavuus](#94-operoitavuus)

**[10. Suunnittelurajoitteet](#10-suunnittelurajoitteet)**

* [10.1 Standardit](#101-standardit)
* [10.2 Laitteistorajoitteet](#102-laitteistorajoitteet)
* [10.3 Ohjelmistorajoitteet](#103-ohjelmistorajoitteet)
* [10.4 Muut rajoitteet](#104-muut-rajoitteet)

**[11. Hylätyt ratkaisuvaihtoehdot](#11-hylätyt-ratkaisuvaihtoehdot)**

**[12. Jatkokehitysajatukset](#12-jatkokehitysajatukset)**

**[Lähteet](#lähteet)**

**[Liitteet](#liitteet)**

## 1. Johdanto

### 1.1 Tarkoitus ja laajuus

Tämä dokumentti on XYZ-järjestelmästä laadittu toiminnallinen määrittely, jossa määritellään...
Järjestelmälle asetettavat vaatimukset on yhdessä asiakkaan…
Dokumentti on tarkoitettu….

### 1.2 Tuote ja sen toimintaympäristö

Kehitettävän/Toteutettavan tuotteen/palvelu nimi on XYZ, joka….
Järjestelmän tarkoitus on palvella ... ja sen tuottama arvo on… tarjota
Tuote/palvelu tullaan julkaisemaan … Järjestelmän käyttäjiä ovat…

### 1.3 Määritelmät

Esim.

* **CSS:** Web-dokumentin tyyliohje.
* **Drupal/WordPress:** Sisällönhallinta järjestelmä.
* **HTML:** Hypertekstin kuvauskieli.
* **JavaScript:** Komentosarjakieli Web-ohjelmointiin.
* **MySQL:** SQL-tietokannan hallintajärjestelmä
* **PHP:** Ohjelmointikieli, jota hyödynnetään dynaamisten Web-sivujen tekemiseen.
* **Tuotteen/palvelun nimi:** Kehitettävän/toteutettavan tuotteen/palvelun lyhenne
* **Toteutusprojektin:** Kehitysprojektin nimi
* **Tech XYZ:** Lyhenne teknologiasta xyz.

## 2. Vaatimukset

Tämä dokumentti on XYZ-järjestelmästä laadittu toiminnallinen määrittely, jossa määritellään...
Järjestelmälle asetettavat vaatimukset on yhdessä asiakkaan…
Dokumentti on tarkoitettu….

### 2.1 Toiminnalliset vaatimukset

#### 2.1.1 Käyttäjävaatimukset

#### 2.1.2 Järjestelmävaatimukset

### 2.2 Ei-toiminnalliset vaatimukset

#### 2.2.1 Suorituskykyvaatimukset

#### 2.2.2 Turvallisuusvaatimukset

## 3. Yleiskuvaus

Kuvataan järjestelmää ja sen ympäristöä, toimintaa, käyttäjiä, rajoitteita, riippuvuuksia ja oletuksia. Tämä luku on eräänlainen yhteenveto siitä, mitä tulevissa kappaleissa on käyty läpi tarkemmin.

### 3.1 Järjestelmän arkkitehtuuri

### 3.2 Käyttäjät ja roolit

### 3.3 Käyttötapaukset

## 4. Tiedot ja tietokanta

Määritellään järjestelmän tietosisältöä, käsitteitä, tietokantaa ja sen käyttöön liittyviä asioita laajemmassa mittakaavassa. Kokonaisuudessaan luku kuvaa tietokannan rakennetta ja sinne kuuluvia tietoja tarkasti.

### 4.1 Tietosisältö

### 4.2 Käyttöintensiteetti

### 4.3 Kapasiteettivaatimukset

### 4.4 Tiedosto- ja asetustiedostot

## 5. Arkkitehtuuri

Kuvataan järjestelmän arkkitehtuuria. Luku pitää sisällään kaavioita järjestelmän fyysisestä, loogisesta ja suunnitteluarkkitehtuurista.

### 5.1 Looginen arkkitehtuuri

### 5.2 Tekninen arkkitehtuuri

## 6. Käyttäjät

Kuvataan järjestelmän käyttäjäryhmät ja niihin kuuluvat käyttäjät, heidän roolinsa ja tehtävänsä järjestelmässä.

### 6.1 Käyttäjäluettelo

### 6.2 Internetin käyttäjät

## 7. Käyttötapaukset ja käyttöliittymä

Kerrotaan ja kuvataan käyttöliittymiä ja niihin liittyviä käyttötapauksia ja toimintoja yksityiskohtaisesti kuvilla ja tekstillä.

### 7.1 Käyttötapaukset

### 7.2 Käyttöliittymien yleiskuvaus

### 7.3 Toiminnot

#### 7.3.1 Toiminto 1

Kuva: Toiminto 1

* Toiminnon nimi
* Toiminnon kuvaus
* Toiminnon tarkoitus
* Toimijat
* Alkuehdot
* Tyypillinen käyttötapauksen kulku (toiminnon määritys) / Vaihtoehtoinen käyttötapauksen kulku
* Syöte
* Virhetilanteet

#### 7.3.2 Toiminto 2

Kuva: Toiminto 2

* Toiminnon nimi
* Toiminnon kuvaus
* Toiminnon tarkoitus
* Toimijat
* Alkuehdot
* Tyypillinen käyttötapauksen kulku (toiminnon määritys) / Vaihtoehtoinen käyttötapauksen kulku
* Syöte
* Virhetilanteet

#### 7.3.3 Toiminto 3

Kuva: Toiminto 3

* Toiminnon nimi
* Toiminnon kuvaus
* Toiminnon tarkoitus
* Toimijat
* Alkuehdot
* Tyypillinen käyttötapauksen kulku (toiminnon määritys) / Vaihtoehtoinen käyttötapauksen kulku
* Syöte
* Virhetilanteet

#### 7.3.4 Toiminto 4

Kuva: Toiminto 4

* Toiminnon nimi
* Toiminnon kuvaus
* Toiminnon tarkoitus
* Toimijat
* Alkuehdot
* Tyypillinen käyttötapauksen kulku (toiminnon määritys) / Vaihtoehtoinen käyttötapauksen kulku
* Syöte
* Virhetilanteet

## 8. Ulkoiset liittymät

Kuvataan sanallisesti sitä, mihin ohjelmistoihin, laitteistoihin ja tietoliikenteeseen järjestelmä liitetään.

### 8.1 Laitteistoliittymä

### 8.2 Ohjelmistoliittymät

### 8.3 Tietoliikenneliittymät

## 9. Muut ominaisuudet

Kerrotaan järjestelmän muista ei-toiminnallisista ominaisuuksista, kuten ylläpidettävyys, vasteajat ja käytettävyys. Luku pitää sisällään näiden määritelmät ja suunnitelmat.

### 9.1 Suorituskyky ja vasteajat

### 9.2 Käytettävyys, toipuminen, turvallisuus, suojaukset

### 9.3 Siirrettävyys ja yhteensopivuus

### 9.4 Operoitavuus

## 10. Suunnittelurajoitteet

Kohdassa käsitellään järjestelmää laadittaessa huomioon otettavat standardit ja muut rajoitteet.

### 10.1 Standardit

### 10.2 Laitteistorajoitteet

### 10.3 Ohjelmistorajoitteet

### 10.4 Muut rajoitteet

## 11. Hylätyt ratkaisuvaihtoehdot

Listaus projektin aikana hylätyistä ratkaisuvaihtoehdoista. Hylätyt ratkaisuvaihtoehdot kuvataan aika- ja asiajärjestyksessä, jossa ne ovat ilmenneet.

## 12. Jatkokehitysajatukset

Jatkokehitysajatuksiin voi kerätä projektin aikana syntyneitä jatkokehitysajatuksia järjestelmälle tulevaisuudessa.

## Lähteet

## Liitteet

Esimerkkejä liitteistä:

* järjestelmän tietokantataulut/tietokantakaavio
* luokkakaavio
* käyttötapauskaavio
* UML-kaavio
* sekvenssikaavio
* arkkitehtuurikuvaukset
* asiakasvaatimukset/esikartoitus
* rautalanka/wire frame
* sivukartta
* käyttöliittymän prototyyppikuvat
* ylläpito-ohje
