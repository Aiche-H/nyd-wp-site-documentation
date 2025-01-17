# Työvaiheet

- [Työvaiheet](#työvaiheet)
  - [Vaihe 1: Suunnittelu (viikko 45-46)](#vaihe-1-suunnittelu-viikko-45-46)
    - [**Vaatimusten määrittely:**](#vaatimusten-määrittely)
    - [**Visuaalisen ilmeen suunnittelu:**](#visuaalisen-ilmeen-suunnittelu)
    - [**Sivustorakenteen suunnittelu:**](#sivustorakenteen-suunnittelu)
  - [Vaihe 2: WordPress-ympäristön valmistelu (viikko 47)](#vaihe-2-wordpress-ympäristön-valmistelu-viikko-47)
    - [**WordPress-teeman valinta ja asennus:**](#wordpress-teeman-valinta-ja-asennus)
    - [**Lisäosien asennus:**](#lisäosien-asennus)
  - [Vaihe 3: Tuotteiden lisääminen (viikko 48-49)](#vaihe-3-tuotteiden-lisääminen-viikko-48-49)
  - [Vaihe 4: Maksu- ja toimitustapojen määrittäminen (viikko 50)](#vaihe-4-maksu--ja-toimitustapojen-määrittäminen-viikko-50)
  - [Vaihe 5: Testaus ja optimointi (viikko 51)](#vaihe-5-testaus-ja-optimointi-viikko-51)
  - [Vaihe 6: Julkaisu ja seuranta (viikko 52)](#vaihe-6-julkaisu-ja-seuranta-viikko-52)

Kun suunnitelma on valmis, on aika aloittaa sovelluksen toteuttaminen. Pidä sovelluksen
työstämisen ajan työpäiväkirjaa. Kirjaa työpäiväkirjaan jokainen päivä, jolloin olet projektia
työstänyt, ja liitä mukaan lyhyt kuvaus siitä, mitä olet päivän aikana tehnyt.
Kun sovellus on valmis, kirjoita tähän lyhyt (puoli sivua riittää, max. 1 sivu) yleiskatsaus
päävaiheista ja niiden etenemisestä. Voit kertoa yleisellä tasolla mm. kuinka ulkoasun tai
toiminnallisuuksien rakentaminen tai integraatioiden luominen sujui.
Lisää työpäiväkirja tämän raportin liitteisiin.

## Vaihe 1: Suunnittelu (viikko 45-46)

### **Vaatimusten määrittely:**

Määritellään tarkasti, mitä verkkokaupan tulee tehdä (tuotteet, maksutavat, toimitustavat jne.).

Verkkokaupan toiminnallisuudet on määritelty alustavasti vastaamaan nykyisiä tarpeita. Tavoitteena on tarjota asiakkaille selkeä ja toimiva ostokokemus.

- **Tuotevalikoima:** Verkkokaupan tuotevalikoima on dynaaminen, ja sitä päivitetään jatkuvasti koska käytetyt esineet ovat vaihtuvia.
- **Maksutavat:** Tällä hetkellä hyväksytään lasku ja maksu noudettaessa. Muita maksutapoja, kuten verkkopankkimaksua, voidaan lisätä tarvittaessa, kun liikevaihto kasvaa ja se koetaan tarpeelliseksi.
- **Toimitustavat:** Tuotteet toimitetaan joko noudettuna myymälästä tai postipakettina.

**Perustelut:**

Päätös rajata maksutavat ja toimitustavat tällä hetkellä perustuu seuraaviin tekijöihin:

- **Pieni liikevaihto ja paikallinen asiakaskunta:** Nykyinen asiakaskunta suosii pääasiassa käteismaksuja ja noutoa myymälästä.
- **Tietoturva:** Verkkopankkimaksun lisääminen vaatii panostuksia tietoturvaan, mikä ei ole perusteltua nykyisellä liikevaihdolla.

**Jatkokehitys:**

Verkkokaupan toiminnallisuuksia kehitetään jatkuvasti muuttuvien tarpeiden mukaisesti. Tulevaisuudessa voidaan harkita seuraavia muutoksia:

- **Lisää maksutapoja:** Verkkopankkimaksun lisääminen, kun liikevaihto kasvaa ja tietoturva on kunnossa.
- **Kansainvälinen toimitus:** Jos tavoitteena on laajentaa toimintaa ulkomaille, on toimitustapoja laajennettava.
- **Integrointi muihin järjestelmiin:** Esimerkiksi kirjanpito- tai varastojärjestelmään.

**Arviointi:**

Vaatimusten määrittely on toteutettu hyvin ottaen huomioon nykyiset resurssit ja liiketoiminnan tarpeet. Päätökset ovat perusteltuja ja joustavia, mikä mahdollistaa verkkokaupan kehittämisen tulevaisuudessa.

### **Visuaalisen ilmeen suunnittelu:**

Luodaan konsepti verkkokaupan ulkoasusta (logot, värit, typografia).

Verkkokaupan visuaalinen ilme on suunniteltu alusta loihtien. Koska yrityksellä ei ollut ennestään visuaalista identiteettiä, luotiin kaikki elementit yhtä aikaa.

**Värimaailma:**

Valitsimme mustan, valkoisen ja harmaan väripaletin, sillä ne viestivät puhtaudesta, järjestelmällisyydestä ja ajattomuudesta. Nämä ominaisuudet koettiin tärkeiksi, kun kyseessä on käytettyjen tuotteiden myynti.

**Logo:**

Logo on suunniteltu yksinkertaiseksi ja muistettavaksi. Se perustuu omistajan kuvaan, joka on käytetty myös muissa kanavissa, kuten YouTube-tilillä. Logon mustavalkoinen ja selkeä linjakuvaus mahdollistaa sen käytön myös tulevaisuudessa, kuten nahkan polttoleimassa. Tavoitteena on, että logo tunnistetaan välittömästi yrityksen omistajaksi.

**Typografia:**

Otsikoihin valittiin vahva ja ajaton Times New Roman Bold -fontti, joka luo arvokkaan ja luotettavan vaikutelman. Leipätekstiin valittiin helppolukuinen Open Sans -fontti, joka parantaa sivuston käytettävyyttä.

**Yhteenveto:**

Verkkokaupan visuaalinen ilme on koherentti ja tukee yrityksen identiteettiä. Valitut värit, logo ja fontit luovat yhdessä tyylikkään ja ammattimaisen kokonaisuuden.

### **Sivustorakenteen suunnittelu:**

Suunnitellaan sivuston rakenne ja sivut (etusivu, tuotesivut, kategoria-sivut, yhteystiedot jne.).

Verkkokaupan sivurakenne on suunniteltu yksinkertaiseksi ja selkeäksi, vastaten pienimuotoisen verkkokaupan tarpeisiin. Sivusto on jaettu seuraaviin pääosiin:

- **Etusivu:** Toimii verkkokaupan pääsisäänkäyntinä ja esittelee yrityksen tärkeimmät ominaisuudet.
- **kaupppa-sivu:** jossa Tuotteiden kategorioittainen haku ja selaus.
- **Historia-sivu:** Yrityksen taustan ja arvojen esittely.
- **Yhteydenottolomake:** Asiakkaan mahdollisuus ottaa yhteyttä yritykseen.
- **Palautuslomake:** Ohjeet tuotteiden palauttamiseen.
- **Tietosuojaseloste:** Selvitys henkilötietojen käsittelystä.
- **Palautusohjeet:** Yksityiskohtaiset ohjeet tuotteiden palauttamiseen.

**Perustelut:**

Tämä sivurakenne on valittu, koska se on:

- **Selkeä ja helppokäyttöinen:** Asiakas löytää tarvitsemansa tiedot helposti.
- **Tehokas:** Sivusto on helppo ylläpitää.
- **Yhteensopiva:** Rakenne soveltuu hyvin pienimuotoisen verkkokaupan tarpeisiin.

**Lisähuomioita:**

- **Sisällön hallintajärjestelmä:** Sivuston rakenne on suunniteltu siten, että sisältöä on helppo päivittää ja muokata sisällönhallintajärjestelmän avulla.
- **Hakukoneoptimointi (SEO):** Sivuston rakenne on suunniteltu tukemaan hakukoneoptimointia, jotta tuotteet löytyvät helposti hakukoneista.
- **Käytettävyys:** Sivuston navigointi on suunniteltu selkeäksi, jotta asiakas löytää tarvitsemansa tiedot mahdollisimman nopeasti.

**Yhteenveto:**

Verkkokaupan sivurakenne on yksinkertainen ja tehokas, ja se vastaa hyvin yrityksen tarpeisiin. Rakenne mahdollistaa selkeän tiedonvälityksen asiakkaalle sekä helppohoitoisen verkkokaupan ylläpidon.

## Vaihe 2: WordPress-ympäristön valmistelu (viikko 47)

### **WordPress-teeman valinta ja asennus:**

Valitaan ja asennetaan sopiva verkkokauppa-teema.

Verkkokauppaprojektiin valittiin WordPress-teemaksi Twenty Twenty-Four. Päätös perustui seuraaviin seikkoihin:

- **Asiakkaan mieltymys:** Asiakas näki useita vaihtoehtoja ja koki Twenty Twenty-Four -teeman ulkoasun sopivaksi verkkokaupan visuaaliseen ilmeeseen.
- **Mukautettavuus:** Vaikka teema on yksinkertainen, se tarjoaa riittävät mahdollisuudet muokkaamiseen. Oma CSS-koodin tarve jäi minimaaliseksi, mikä helpottaa tulevaisuuden ylläpitoa ja päivityksiä.
- **Yhteensopivuus:** Teema on täysin yhteensopiva WooCommerce-lisäosan kanssa, eikä aiheuttanut ongelmia verkkokaupan toiminnallisuuksien kanssa.
- **Päivitykset:** Koska kyseessä on WordPressin oma teema, voidaan olettaa, että sitä päivitetään aktiivisesti pitkään, mikä takaa turvallisuuden ja yhteensopivuuden uusimpien WordPress-versioiden kanssa.

**Vertailtuja vaihtoehtoja:**

Vertailussa olivat mukana myös Kadence, OceanWP ja Black&White -teemat. Nämä teemat eivät kuitenkaan täyttäneet kaikkia projektin vaatimuksia, sillä niissä ilmeni esimerkiksi asetteluongelmia, yhteensopivuusongelmia WooCommerce-lisäosan kanssa tai rajoitettuja muokkaamismahdollisuuksia.

**Yhteenveto:**

Twenty Twenty-Four -teeman valinta osoittautui oikeaksi päätökseksi, sillä se täyttää projektin vaatimukset ja tarjosi hyvän pohjan verkkokaupan rakentamiselle.

### **Lisäosien asennus:**

Asennetaan tarvittavat lisäosat (maksutavat, toimitustavat, SEO jne.).

## Vaihe 3: Tuotteiden lisääminen (viikko 48-49)

**Tuotteiden lisääminen manuaalisesti:**

*   **Tuotteiden syöttö:** Koska käytössä ei ole aiempaa tuotetietokantaa, syötetään kaikki tuotetiedot (nimi, kuvaus, hinta, varasto, jne.) manuaalisesti WooCommerce-hallintapaneelin kautta.
*   **Tuotekuvien lisääminen:** Jokaiselle tuotteelle lisätään laadukkaat tuotekuvat, jotka helpottavat asiakasta hahmottamaan tuotteen ominaisuudet.

**Kategorioiden luominen ja hallinta:**

*   **Alustavat kategoriat:** Viikoilla 48-49 luodaan alustavat tuoteryhmät ja alaluokat, jotka kattavat suurimmat tuotekategoriat.
*   **Joustava kategorisointi:** Koska tuotevalikoima voi muuttua nopeasti, kategorioita tarkastellaan ja muokataan säännöllisesti. Uusia kategorioita luodaan tarpeen mukaan, jotta tuotteet löytyvät helposti.
*   **Toistavaran erityispiirteet:** Otetaan huomioon toistavaran myynnin erityispiirteet kategorisoinnissa. Esimerkiksi voidaan luoda kategoria "Käytetyt elektroniikkatuotteet" ja sen alle alaluokat eri laitetyypeille.

**Tämän vaiheen tavoitteena on:**

*   Saada kaikki myytävät tuotteet näkyviin verkkokaupassa.
*   Luoda selkeä ja looginen tuotekategorisointi, joka helpottaa asiakkaiden navigointia.
*   Varustaa tuotteet tarvittavilla tiedoilla, kuten kuvauksilla ja kuvilla.

**Huom:** Koska tuotevalikoima on aluksi vielä muotoutumassa, on tärkeää säilyttää joustavuus kategorioiden suhteen. Säännöllinen kategorioiden tarkastelu ja muokkaaminen varmistaa, että tuotteet löytyvät helposti ja asiakaskokemus on mahdollisimman hyvä.

## Vaihe 4: Maksu- ja toimitustapojen määrittäminen (viikko 50)

**Maksutavat:**

*   **Nouto paikan päältä:** Säilytetään olemassa oleva noutotapa maksun yhteydessä.
*   **Verkkopankkimaksut:** Integroidaan haluttu verkkopankkimaksupalvelu (esim. Checkout Finland, Stripe Connect) mahdollistamaan sujuvat verkkopankkimaksut.
*   **Muut maksutavat:** Harkitaan muiden maksutapojen (esim. luottokortit, lasku) lisäämistä asiakaskunnan tarpeiden mukaan.

**Toimitustavat:**

*   **Nouto paikan päältä:** Pääasiallinen toimitustapa on edelleen nouto myyntipisteestä.
*   **Postitus:** Jos asiakas toivoo postitusta, voidaan tarjota postituspalveluita (esim. Posti, Matkahuolto) ja määrittää niihin liittyvät kulut.
*   **Muut toimitustavat:** Harkitaan muita toimitustapoja (esim. kuljetus yrityksen toimesta) tarpeen mukaan.

**Tämän vaiheen tavoitteena on:**

*   Tarjota asiakkaille joustavia maksuvaihtoehtoja.
*   Määrittää selkeät toimitustavat ja niihin liittyvät kulut.
*   Helpottaa kassaprosessia sekä asiakkaalle että myyjälle.

**Huomiot:**

*   **Maksutapojen valinta:** Valittavat maksutavat tulee valita huolella ottaen huomioon asiakaskunnan toiveet, verkkokaupan ominaisuudet ja kustannukset.
*   **Toimituskulujen määrittäminen:** Toimituskulut tulee määrittää selkeästi ja läpinäkyvästi. Voidaan käyttää esimerkiksi paino- tai tilavuusperusteisia hinnoittelutapoja.
*   **Maksujen käsittely:** Varmista, että valitut maksupalvelut integroituvat saumattomasti verkkokauppaan ja että maksujen käsittely on turvallista.
*   **Toimitusajan arviointi:** Määritä realistisesti toimitusajat eri toimitustavoille.

## Vaihe 5: Testaus ja optimointi (viikko 51)

**Testaus ja kehittäminen:**

*   **Toiminnallisuuksien perusteellinen testaus:** Kaikki verkkokaupan toiminnot (ostoskori, maksu, rekisteröityminen, tuotteiden haku, kategorianäkymät jne.) testattiin huolellisesti eri selaimilla ja laitteilla. Kaikki havaitut virheet korjattiin välittömästi.
*   **SEO-optimoinnin aloittaminen:** Aloitettiin sivuston SEO-optimointi keskittyen tärkeimpiin avainsanoihin. Määriteltiin sivukohtaiset metatiedot (otsikko, kuvaus) ja parannettiin sisällön rakennetta.
*   **Responsiivisuuden varmistaminen:** Varmistettiin, että verkkokauppa näyttää ja toimii hyvin eri näytönkokoisilla laitteilla (mobiili, tabletti, tietokone).

**Tulokset:**

*   **Toiminnallisuus:** Kaikki verkkokaupan toiminnot toimivat odotetusti.
*   **SEO:** SEO-optimoinnilla on hyvä alku, mutta jatkokehitys on tarpeen.
*   **Responsiivisuus:** Verkkokauppa toimii hyvin eri laitteilla, eikä merkittäviä ongelmia havaittu.

**Muuta:**

*   **Turhan median poisto:** Viikon aikana poistettiin turhaa mediaa (kuvia, videoita) parantaaksemme sivuston latausnopeutta.
*   **Jatkotoimet:** Jatketaan SEO-optimointia ja seurataan sivuston suorituskykyä analytiikkatyökalujen avulla.

**Tämän vaiheen tavoitteena oli:**

*   Varmistaa, että verkkokauppa on valmis julkaistavaksi.
*   Aloittaa sivuston optimointi hakukoneille.
*   Parantaa käyttäjäkokemusta.

**Yhteenveto:**

Verkkokaupan testausvaihe on saatu päätökseen ja kaikki olennaiset toiminnot toimivat odotetusti. SEO-optimointi on hyvässä alussa ja responsiivisuus on kunnossa. Jatkossa keskitytään SEO-optimoinnin kehittämiseen ja käyttäjäpalautteen keräämiseen.

## Vaihe 6: Julkaisu ja seuranta (viikko 52)

**Julkaisu ja käyttöönotto:**

*   **Verkkokaupan siirto tuotantoon:** Verkkokauppa siirrettiin onnistuneesti pilvipalvelimelle.
*   **Julkaisu:** Verkkokauppa julkaistiin ja on nyt avoinna asiakkaille.
*   **Ensimmäiset tilaukset:** Seurataan tarkasti ensimmäisiä tilauksia ja niiden käsittelyä.

**Analytiikka:**

*   **WooCommerce-analytiikan käyttöönotto:** WooCommerce-analytiikka on asennettu ja tuottaa ensimmäisiä tietoja verkkokaupan toiminnasta.
*   **Muiden työkalujen harkinta:** Harkitaan muiden analytiikkatyökalujen (esim. Google Analytics, Google Search Console) käyttöönottoa laajemman kuvan saamiseksi.

**Koulutus ja tuki:**

*   **Peruskoulutus:** Asiakkaalle on annettu peruskoulutus verkkokaupan hallintapaneelin käyttöön.
*   **Ylläpito-ohjeet:** Asiakkaalle on toimitettu kattavat ylläpito-ohjeet, joissa käydään läpi tärkeimmät toimenpiteet (tuotteiden lisääminen, tilausten hallinta jne.).
*   **Tarpeen mukainen tuki:** Tarjoamme asiakkaalle jatkuvaa tukea tarpeen mukaan.

**Tämän vaiheen tavoitteena oli:**

*   Saada verkkokauppa toimimaan tuotantoympäristössä.
*   Aloittaa verkkokaupan seuranta ja analysointi.
*   Varmistaa, että asiakas osaa käyttää verkkokauppaa.

**Tulokset:**

*   Verkkokauppa on nyt avoinna asiakkaille.
*   WooCommerce-analytiikka tuottaa ensimmäisiä tietoja.

**Jatkotoimet:**

*   **Analytiikan syventäminen:** Hyödynnetään WooCommerce-analytiikan tietoja ja harkitaan muiden työkalujen käyttöönottoa.
*   **Käyttäjäpalautteen kerääminen:** Kerätään käyttäjäpalautetta verkkokaupan toiminnasta ja kehitetään sitä sen pohjalta.

**Yhteenveto:**

Verkkokauppa on nyt julkaistu ja ensimmäiset askeleet sen seurannassa on otettu. Jatkossa keskitytään verkkokaupan kehittämiseen ja kasvattamiseen.
