# Suunnitelma projektin toteuttamiseksi

Tässä luvussa esitellään suunnitelma, jonka pohjalta verkkopalvelu rakennetaan. Luo suunnitelma
vaihe vaiheelta alla olevien alalukujen avulla: toimi ensin alaluvun 2.1 ohjeiden mukaan ja
kirjoita vaaditut asiat tähän raporttipohjaan, ja kun olet valmis, siirry seuraavaan alalukuun ja
sen ohjeistukseen. Palaa tarvittaessa takaisin muokkaamaan aiempien vaiheiden
dokumentointia, mikäli huomaat, että olet unohtanut huomioida jonkin näkökulman (esim.
käyttötapausta luodessasi teet uuden esteettömyyteen liittyvän havainnon, jota et ole vielä
huomioinut).
Tähän kohtaan (yläluvun 2 ja alaluvun 2.1 väliin) ei tarvitse kirjoittaa mitään. Poista nämä
ohjeet tästä, kun et niitä enää tarvitse. Voit poistaa myös alalukujen ohjeet sen jälkeen, kun
olet saanut kyseisen alaluvun tekstin kirjoitettua.

## Asiakkaan tarpeet ja suunnittelun raamit

### Miksi verkkopalvelu luodaan?

Verkkopalvelu luodaan, jotta NYD voi tehostaa myyntiä, parantaa asiakaskokemusta, automatisoida prosesseja. Verkkopalvelun avulla NYD pääsee eroon jatkuvasta päivttelystä usealla alustalla.

### Kohderyhmä

Verkkopalvelun kohderyhmänä ovat asiakkaat, työntekijät ja mahdollilset kumppanit. He käyttävät verkkopalvelua, jotta Asiakkaat voivat tehdä ostoksia helposti, seurata tilauksiaan ja kommunikoida yrityksen kanssa.

### Aiemmat ratkaisut ja muutos

**Nykytila:** Asiakas hoitaa asiakastilaukset pääasiassa sähköpostilla ja Excel-taulukoilla. Tämä johtaa helposti virheisiin, tiedon häviämiseen ja vaikeuttaa tilausten seurantaa.

**Uusi verkkopalvelu:** Uusi verkkopalvelu automatisoi tilausprosessin, tarjoaa keskitetyn näkymän kaikkiin tilauksiin ja mahdollistaa reaaliaikaisen seurannan.

## Tavoitteet

Verkkopalvelun tavoitteena on:

1. **Vähentää manuaalista työmäärää:**
   * Automatisoida toistuvat työtehtävät, kuten tilaus käsittely, laskutus ja asiakastietojen päivitys.
   * Keskittää tiedot yhteen paikkaan, jotta tiedon etsiminen ja päivittäminen olisi tehokkaampaa.
   * Vähentää virheiden määrää automatisoimalla rutiinitehtäviä.

2. **Parantaa ammatillista luotettavuutta:**
   * Tarjota asiakkaille reaaliaikaista tietoa tilauksista ja toimituksista.
   * Varmistaa, että kaikki asiakastiedot ovat ajan tasalla ja helposti saatavilla.
   * Parantaa asiakaspalvelun laatua keskittämällä kaikki asiakasvuorovaikutus yhteen kanavaan.

3. **Helpottaa asiakaskommunikaatiota:**
   * Keskittää kaikki asiakasviestit yhteen paikkaan, jotta tiedot eivät häviä.
   * Mahdollistaa nopeamman ja tehokkaamman viestinnän asiakkaiden kanssa.

**Lisäksi Verkkopalvelun avulla voidaan saavuttaa seuraavia hyötyjä:**

* **Parantaa asiakaskokemusta:** Asiakkaat saavat nopeampaa ja henkilökohtaisempaa palvelua.
* **Lisätä myyntiä:** Tehokkaampi toiminta ja parempi asiakaskokemus voivat johtaa myynnin kasvuun.

**Näiden tavoitteiden pohjalta voidaan määritellä tarkemmat toiminnallisuudet, kuten:**

* **Asiakasportaali:** Asiakkaat voivat itse seurata tilauksiaan, tehdä palautuksia ja ottaa yhteyttä asiakaspalveluun.
* **Automaattiset ilmoitukset:** Asiakkaat saavat automaattisesti ilmoituksia tilauksen etenemisestä, toimituksesta ja laskusta.
* **Keskitetty tietokanta:** Kaikki asiakas- ja tilaustiedot tallennetaan yhteen paikkaan, mikä helpottaa tiedon hallintaa ja raportointia.
* **Integrointi muihin järjestelmiin:** verkkopalvelu voidaan integroida esimerkiksi kirjanpito- ja varastojärjestelmiin, jotta tiedonsiirto olisi automatisoitua.

**Tärkeintä on, että verkkopalvelu tukee yrityksen liiketoimintatavoitteita ja helpottaa työntekijöiden arkea.**

## Toiminnallisuudet ja tekniset ratkaisut

**Asiakaspuolen toiminnot:**

* **Itsepalveluportaali:**
  * Tilin luominen ja hallinta
  * Laskujen maksu ja lataus
  * Tuotteiden palautuspyynnöt

* **Sosiaalisen median integraatiot:**
  * Jakaminen sosiaalisessa mediassa
  * Arvostelujen kerääminen

**Yrityksen sisäiset toiminnot:**

* **Tilausten hallinta:**
  * Tilausten vastaanotto, käsittely ja lähetys
  * Varastonhallinta
  * Laskutus ja maksujen seuranta
  * Palautusten käsittely

* **Raportointi:**
  * Myynnin seuranta
  * Asiakaskäyttäytymisen analysointi

**Tekniset ratkaisut:**

* **E-commerce-alusta:** WooCommerce
* **Maksupalvelut:** lasku ja paikanpäällä noudon yhteydessä maksaminen
* **Tietokanta:** wordpressin automaattinen tietokanta.
* **Kehys:** wordpress twenty-twenty-four teema.

| Toiminnallisuus | Tekninen toteutus | Syy |
|---|---|---|
| Tilausten tekeminen | Woocommers lisäosan avulla | Asiakkaalle on tärkeää että tilaus toiminto on olemassa että myyntiä tapahtuu |
| Tilausten seuranta | Reaaliaikainen tietokanta, käyttäjäystävällinen käyttöliittymä | Asiakas voi seurata tilauksen etenemistä helposti |
| Tuotteiden palautuspyynnöt | Lomake, joka lähettää tiedot automaattisesti | Nopeuttaa palautusprosessia |
| Varastonhallinta | Integraatio kirjanpitojärjestelmään, reaaliaikainen varaston saldo | Vähentää sekaannuksia verrattuna moneen eri alustalla myyntiin |

* **Käytettävyys:** Verkkopalvelun tulee olla helppokäyttöinen niin asiakkaille kuin työntekijöille.
* **Turvallisuus:** Tietoturva on erityisen tärkeä, kun käsitellään asiakastietoja ja maksutapahtumia.
* **Skaalautuvuus:** Verkkopalvelun tulee pystyä kasvamaan yrityksen mukana.
* **Ylläpidettävyys:** Verkkopalvelun tulee olla helppo ylläpitää ja päivittää.

## Graafinen linjaus

* **Asiakkaan ydinarvot:** Luotettavuus, Kestävyys, yksinkertaisuus
* **brändin persoonallisuus:** Moderni ja minimalistinen Musta-valkoinen yhdistelmä on usein liitetty moderniin ja minimalistiseen estetiikkaan. Se voi viestiä selkeydestä, tyylikkyydestä ja ajattomuudesta.

**Visuaalisen ilmeen elementit:**

* **Väripaletti:** musta, valkoinen, harmaa
* **Typografia:** Valitse fontteja, jotka ovat helppolukuisia ja tukevat brändin ilmettä.
* **Kuvitus ja ikonit:** Luo tai valitse kuvitusta ja ikoneita, jotka ovat visuaalisesti kiinnostavia ja tukevat brändin tarinaa.
* **Kuviot ja tekstuurid:** Käytä kuvioita ja tekstureita luodaksesi syvyyttä ja mielenkiintoa suunnitteluun.

## Jatkokehitysideat

Kirjoita ylös prosessin aikana tulleet ideat, joita - ei syystä tai toisesta – toteuteta tämän
projektin aikana. Ideat lisäävät mahdollisuutta kasvattaa asiakastoimeksiantoa
myöhemminkin. Voit myös perustella miksi ideaa ei lähdetty suunnittelemaan tai
toteuttamaan tässä vaiheessa.

* **UKK-osio:** Luo usein kysytyt kysymykset -osio. tämä on mahdollista sen jälkeen kun on saatu jotain kontaktia asiakkaiden kanssa ensin

## Esteettömyys ja käytettävyys

Saavutettavuusdirektiivi korostaa, että digitaaliset palvelut tulee suunnitella siten, että ne ovat mahdollisimman monelle käyttäjälle saavutettavia. Tämä tarkoittaa, että Verkkopalvelun tulee olla helppokäyttöinen kaikille, myös henkilöille, joilla on esimerkiksi näkö-, kuulo- tai liikuntarajoitteita.

### Visuaalinen toteutus

* **Värit:** Varmista, että väriyhdistelmät ovat riittävän kontrastit, jotta teksti erottuu taustasta. Käytä värisokeutta huomioivia paleteja.
* **Typografia:** Valitse selkeät ja helppolukuiset fontit, riittävän suuri fonttikoko ja riittävä rivinväli. Vältä koristeellisia fontteja.
* **Kuvat ja grafiikka:** Käytä kuvatekstejä ja vaihtoehtoisia tekstejä kuville. Varmista, että kuvat ovat selkeitä ja informatiivisia.
* **Sijoittelu:** Käytä selkeää ja loogista sivurakennetta. Hyödynnä valikoita ja välilehtiä, joiden avulla käyttäjä voi liikkua verkkopalvelussa helposti.
* **Riittävä tila:** Varmista, että painikkeiden ja muiden elementtien välillä on riittävästi tilaa, jotta niitä on helppo käyttää.

### Toiminnallisuudet

* **Näppäimistön tuki:** Varmista, että kaikki toiminnot ovat käytettävissä näppäimistön avulla.
* **Kosketusnäyttö:** Optimoi verkkopalvelu kosketusnäytön käyttöön. Varmista, että painikkeet ovat riittävän suuria.
* **Ääniohjaus:** Harkitse ääniohjauksen mahdollistamista.
* **Erilaiset laitteet:** Testaa verkkopalvelu eri laitteilla ja selaimilla.
* **Hidas latausaika:** Optimoi Verkkopalvelun latausaika, jotta käyttäjän kärsivällisyys ei koitu.

### Haasteet ja niiden ratkaisut

* **Näkörajoitteet:** Tarjoa mahdollisuus muuttaa tekstin kokoa ja väriä. Käytä ääni- ja kosketuspalautetta.
* **Kuulorajoitteet:** Käytä tekstityksiä videoissa ja äänimateriaaleissa. Tarjoa mahdollisuus muuttaa äänenvoimakkuutta.
* **Liikuntarajoitteet:** Varmista, että verkkopalvelu toimii hyvin erilaisilla tuen laitteilla, kuten näppäimistöillä, hiirellä ja kosketusnäytöllä.

### Apua verkko palvelun käyttöön

* **Yhteydenottolomake:** Tarjoa mahdollisuus ottaa yhteyttä asiakaspalveluun.
* **Video-ohjeet:** Luo video-ohjeita verkkopalvelun käyttöön.

**Käyttäjäkohderyhmä:**

On tärkeää tuntea verkkopalvelun käyttäjäkohderyhmä, jotta voidaan suunnitella verkkopalvelu heidän tarpeitaan vastaavaksi. Esimerkiksi, jos verkkopalvelu on suunnattu ikääntyneille käyttäjille, on erityisen tärkeää kiinnittää huomiota fonttikokoon, kontrasteihin ja yksinkertaiseen käyttöliittymään.

**Yhteenveto:**

Esteettömyys ja käytettävyys ovat keskeisiä tekijöitä, kun suunnitellaan verkkopalvelua. Huomioimalla kaikki käyttäjät ja heidän erityistarpeensa, voidaan luoda verkkopalvelu, joka on miellyttävä ja helppokäyttöinen kaikille.

## Tietoturva

### Tietoturvan huomioiminen verkkokaupassa

**1. Tiedon salaus:**

* **Salasanat hashataan:** Käyttäjien salasanat tallennetaan hash-muodossa, jolloin niitä ei voida lukea selväteksti muodossa.

**2. Päivitykset:**

* **Ohjelmistot ja lisäosat päivitetään säännöllisesti:** Tämä varmistaa, että mahdolliset tietoturva-aukot korjataan nopeasti.
* **Verkkoalustan päivitykset:** Seurataan aktiivisesti verkkokauppa-alustan päivityksiä ja varmistetaan, että ne asennetaan ajoissa.

**3. Muut suojausmekanismit:**

* **Intruusiontunnistusjärjestelmät:** Seurataan epäilyttävää toimintaa palvelimilla.

**4. Varmuuskopiot:**

* **Säännölliset varmuuskopiot:** Varmistaaksemme, että tiedot voidaan palauttaa, jos järjestelmässä tapahtuu häiriöitä.

### Mahdolliset tietoturvaongelmat ja niiden ennaltaehkäisy

* **Tietovuoto:**
  * **Ennaltaehkäisy:** Rajoitetaan pääsyä herkkiin tietoihin, käytetään vahvoja salasanoja ja seurataan järjestelmälokikirjoja.
* **Phishing-hyökkäykset:**
  * **Ennaltaehkäisy:** Tietoturvakoulutus asiakkaille, jotta he osaisivat tunnistaa phishing-viestit.
* **DDoS-hyökkäykset:**
  * **Ennaltaehkäisy:** Yhteistyö palveluntarjoajan kanssa DDoS-suojauksen varmistamiseksi.
* **Ohjelmistovirheet:**
  * **Ennaltaehkäisy:** Perusteellinen testaus ja säännölliset päivitykset.

### Miten nämä ongelmat voidaan huomioida ja mahdollisesti ennaltaehkäistä?

* **Riskianalyysi:** Säännöllinen riskianalyysi auttaa tunnistamaan mahdolliset tietoturvaheikkoudet.
* **Tietoturva-auditointi:** Ulkopuolinen tietoturva-auditointi voi paljastaa yllättäviä haavoittuvuuksia.
* **Päiväkirjojen seuranta:** Järjestelmälokikirjojen säännöllinen tarkkailu auttaa havaitsemaan epäilyttävää toimintaa.
* **Varmuuskopioiden testaus:** Säännöllinen varmuuskopioiden testaus varmistaa, että tiedot voidaan palauttaa tarvittaessa.
* **Yhteistyö palveluntarjoajan kanssa:** Hyvä yhteistyö palveluntarjoajan kanssa on tärkeää, jotta voidaan varmistaa palveluiden tietoturva.

## Käyttötapaukset

### Käyttötapaus 1: Anna, käsityöharrastaja

**Tausta:** Anna on 35-vuotias grunge-tyylinen intohimoinen pukeutuja, joka etsii jatkuvasti uniikkeja asusteita täydentämään tyyliään. Hän seuraa aktiivisesti muotiblogeja ja -verkostoja löytääkseen tuoreimmat trendit.

**Ongelma:** Annan on vaikea löytää laadukkaita nahkalaukkuja, jotka vastaisivat hänen persoonallisia vaatimuksiaan. Hän haluaa laukun, joka on sekä kestävä että tyylikäs, mutta useimmat löytämänsä laukut ovat liian perinteisiä tai eivät erotu massasta.

**Ratkaisu:** Anna löytää verkkosivun facebookista, joka erottuu rohkealla tyylillään ja lupaa uniikkeja nahkatuotteita. Hän päättää tutustua sivustoon tarkemmin.

**Käyttö:**

* Anna selailee sivuston tuotekategorioita ja suodattaa tuloksia "nahkalaukut"-osiosta. Hän on innoissaan laukun joka sopiii hänen tyyliinsä.
* Anna löytää täydellisen nahkalaukun, jossa on rohkeat yksityiskohdat ja vintage-henkinen ilme. Hän lisää tuotteen ostoskoriin ja suorittaa maksun.
* Anna seuraa verkkokaupan sosiaalisen median kanavia pysyäkseen ajan tasalla uusimmista tuotteista ja kampanjoista.

**Haasteet:**

* Anna voisi toivoa, että sivustolla olisi enemmän valikoimaa.

**Tunteet ja asenteet:**
Anna on erittäin tyytyväinen löytämäänsä laukkuun. Hän kokee, että laukku on täydellinen täydennys hänen tyylilleen ja että se erottaa hänet massasta. Hän arvostaa verkkokaupan yksinkertaisuutta ja helppokäyttöisyyttä.

### Käyttötapaus 2: Verkkokaupan omistaja

**Tausta:** Omistaja on perustanut verkkokaupan, jossa hän myy kirpputorilta löytämiään vintage-vaatteita ja itse tekemiään käsitöitä. Hän haluaa kasvattaa liiketoimintaansa ja tavoittaa uusia asiakkaita.

**Ongelma:** Vaikka omistaja onkin innostunut myymään tuotteitaan verkossa, hänellä ei ole aiempaa kokemusta verkkokaupan hallinnoinnista. Hän tarvitsee selkeät ohjeet uusien tuotteiden lisäämiseen.

**Ratkaisu:** Omistaja löytää [Ylläpitoohjeista](./04-ylläpito-ohjeet.md) ohjevideon, jossa selitetään yksinkertaisesti tuotteen lisäämisen vaiheet. Hän seuraa video-ohjetta ja lisää ensimmäisen vintage-takkinsa myyntiin.

**Käyttö:**

* Omistaja valitsee "Lisää uusi tuote" -vaihtoehdon hallintapaneelissa.
* Hän täyttää tuotteen tiedot, kuten nimi, kuvaus, hinta ja koko.
* Omistaja lisää tuotteeseen useita korkealaatuisia kuvia eri kulmista.
* Hän valitsee tuotteen kategorian "Käytetyt vaatteet".
* Omistaja julkaisee tuotteen.
* Omistaja seuraa tuotteen myyntiä ja saa ilmoituksen, kun tuote on myyty.

**Haasteet:**

* Omistaja miettii, kuinka hän voi optimoida tuotteensa hakukoneille, jotta enemmän asiakkaita löytäisi ne.

**Tunteet ja asenteet:**
Omistaja on helpottunut, kun hän onnistuu lisäämään ensimmäisen tuotteen. Hän on innoissaan siitä, että voi nyt helposti hallinnoida verkkokauppaansa.

## Haasteiden tunnistus

**Verkkokauppa, joka myy nahkakäsitöitä ja käytettyjä tuotteita, voi kohdata seuraavia haasteita:**

### Tuotekuvausten ja -tietojen hallinta

* **Tuotteiden yksilöllisyys:** Jokainen käytetty tuote on uniikki, mikä vaatii yksityiskohtaisia kuvauksia ja mahdollisesti lisätietoja tuotteen kunnosta ja historiasta.
* **Tekniset tiedot:** Nahkatuotteiden kohdalla voi olla tarve ilmoittaa nahan tyyppi, hoito-ohjeet ja muut tekniset tiedot.
* **Kokojen ja mittojen ilmoittaminen:** Käytettyjen vaatteiden ja asusteiden kohdalla on tärkeää ilmoittaa tarkat koot ja mitat.

### Tuotekuvien laatu

* **Valokuvaus:** Hyvät tuotekuvat ovat erityisen tärkeitä, jotta asiakas saa realistisen käsityksen tuotteen kunnosta ja ulkonäöstä.
* **Erilaiset materiaalit:** Nahka, tekstiilit ja muut materiaalit vaativat erilaista valaistusta ja kuvaustekniikkaa.

### Logistiikka ja varastointi

* **varasto tilan puute:** aloittelevalla yrittäjällä ei riitä budjetti varasto toimintaan joten on haasteelista pitää kirjaa varaston tilasta.
* **Toimitukset:** pien yyrittäjänä joudumme kuottamaan postiin ja muihin yleisiin kuljetus menetelmiin jolloin mentämme hallinnan kuljetus prosessista.

### Asiakaspalautukset

* **Käytetyt tuotteet:** Käytettyjen tuotteiden palautukset voivat olla monimutkaisempia, erityisesti jos tuote on vaurioitunut kuljetuksen aikana.
* **Hygieniasyyt:** Vaatteiden ja asusteiden palautukset voivat aiheuttaa hygieniallisia haasteita.

### Kilpailu

* **Monipuoliset verkkokaupat:** Kilpailu on kovaa, ja monissa verkkokaupoissa on laaja valikoima käytettyjä ja uusia tuotteita.
* **Hinnat:** On tärkeää löytää oikea hinnoittelu, joka houkuttelee asiakkaita mutta on myös kannattava.

### Tekniset haasteet

* **Verkkoalusta:** Sopivan verkkokauppa-alustan valinta on tärkeää, jotta voidaan hallita erilaisia tuotteita ja niihin liittyviä tietoja.
* **Maksujärjestelmät:** Turvallisten ja luotettavien maksutapojen integrointi.
* **Hakukoneoptimointi:** Verkkokaupan näkyvyyden parantaminen hakukoneissa.

### Miten näihin haasteisiin voidaan vastata?

* **Yksityiskohtaiset tuotetiedot:** Käytä attribuutteja, kuten koko, väri, materiaali, kunto ja lisätiedot.
* **Laadukkaat tuotekuvat:** Investoi hyvään kameraan ja valaistukseen.
* **Selkeä palautuskäytäntö:** Määritä selkeät säännöt palautuksista ja hyödynnä kuluttajansuojalainsäädäntöä.
* **Kilpailukykyinen hinnoittelu:** Vertaile kilpailijoiden hintoja ja tarjoa lisäarvoa esimerkiksi ilmaiseksi toimituksella tai alennuksilla.
* **Asiakaspalvelu:** Tarjoa nopeaa ja ystävällistä asiakaspalvelua.
* **Markkinointi:** Hyödynnä sosiaalista mediaa, sähköpostimarkkinointia ja muita kanavia tavoittaaksesi kohderyhmäsi.

## Aikataulu

### Vaihe 1: Suunnittelu (viikko 45-46)

* **Vaatimusten määrittely:** Määritellään tarkasti, mitä verkkokaupan tulee tehdä (tuotteet, maksutavat, toimitustavat jne.). (2-3 päivää)
* **Visuaalisen ilmeen suunnittelu:** Luodaan konsepti verkkokaupan ulkoasusta (logot, värit, typografia). (3-4 päivää)
* **Sivustorakenteen suunnittelu:** Suunnitellaan sivuston rakenne ja sivut (etusivu, tuotesivut, kategoria-sivut, yhteystiedot jne.). (2-3 päivää)

### Vaihe 2: WordPress-ympäristön valmistelu (viikko 47)

* **WordPress-teeman valinta ja asennus:** Valitaan ja asennetaan sopiva verkkokauppa-teema. (2 päivää)
* **Lisäosien asennus:** Asennetaan tarvittavat lisäosat (maksutavat, toimitustavat, SEO jne.). (2 päivää)

### Vaihe 3: Tuotteiden lisääminen (viikko 48-49)

* **Tuotteiden tuonti:** Tuodaan tuotteet esimerkiksi CSV-tiedostosta. (3-4 päivää)
* **Kategorioiden luominen:** Luodaan tuoteryhmät ja alaluokat. (2 päivää)

### Vaihe 4: Maksu- ja toimitustapojen määrittäminen (viikko 50)

* **Maksutapajen integrointi:** Integroidaan halutut maksutavat (esim. PayPal, Stripe). (2-3 päivää)
* **Toimitustapojen määrittäminen:** Määritellään toimitustavat ja -kulut. (1-2 päivää)

### Vaihe 5: Testaus ja optimointi (viikko 51)

* **Toiminnallisuuksien testaus:** Testataan kaikki verkkokaupan toiminnot (ostoskori, maksu, rekisteröityminen). (3-4 päivää)
* **SEO-optimointi:** Optimoidaan sivusto hakukoneille (avainsanat, metatieto). (2 päivää)
* **Responsiivisuuden testaus:** Varmistaan, että verkkokauppa toimii hyvin eri laitteilla. (1 päivä)

### Vaihe 6: Julkaisu ja seuranta (viikko 52)

* **Verkkokaupan julkaisu:** Julkaistaan verkkokauppa tuotantoympäristöön. (1 päivä)
* **Analytiikkatyökalujen asennus:** Asennetaan muut tarvittavat työkalut. (1 päivä)
* **Koulutus:** Koulutetaan asiakas verkkokaupan käyttöön. (2 päivää)

**Taulukkoesitys:**

| Viikko | Vaihe | Tehtävät |
|---|---|---|
| 45-46 | Suunnittelu | Vaatimusten määrittely, visuaalinen suunnittelu, sivustorakenne |
| 47 | Valmistelu | Hosting, teema, lisäosat |
| 48-49 | Tuotteiden lisääminen | Tuotteiden tuonti, muokkaus, kategoriat |
| 50 | Maksu ja toimitus | Maksutavat, toimitustavat |
| 51 | Testaus ja optimointi | Toiminnallisuuksien testaus, SEO, responsiivisuus |
| 52 | Julkaisu ja seuranta | Julkaisu, analytiikka, koulutus |
