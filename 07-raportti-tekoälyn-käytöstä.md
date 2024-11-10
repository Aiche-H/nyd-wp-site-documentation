# Raportti teköälyn käytöstä

- [Raportti teköälyn käytöstä](#raportti-teköälyn-käytöstä)
  - [Tekoälyn käyttöön liittyvät tavoitteet](#tekoälyn-käyttöön-liittyvät-tavoitteet)
  - [Tekoälyn valinta ja valinnan perustelu](#tekoälyn-valinta-ja-valinnan-perustelu)
  - [Tekoälyn käyttöönotto ja soveltaminen](#tekoälyn-käyttöönotto-ja-soveltaminen)
  - [Tulokset ja tulosten analyysi](#tulokset-ja-tulosten-analyysi)
  - [Reflektio ja oma oppiminen](#reflektio-ja-oma-oppiminen)
  - [Liitteet, lähteet ja linkit](#liitteet-lähteet-ja-linkit)

## Tekoälyn käyttöön liittyvät tavoitteet

- Mitkä olivat tavoitteesi tekoälyn käytölle tässä projektissa?
  - helpottaa käännösten kanssa, avustaa täyte tekstin ja tuotekuvausten luonnissa muutamat kuvat myös luotu tekoälyllä.
- Miten arvioit, että tekoäly auttoi sinua saavuttamaan nämä tavoitteet?
  - Tekoäly nopeutti merkittävästi työskentelyä, vaikka tekstejä joutuikin tarkistamaan ja korjaamaan useammin. Silti prosessi oli huomattavasti tehokkaampi kuin manuaalinen kääntäminen ja keksiminen. Tekoäly oli erityisen hyödyllinen pilkkujen ja pisteiden asettamisessa, mikä on minulle haastavaa.
- Miten suunnittelit tekoälyn käytön omassa projektissasi?
  - Tekoälyn käyttöä suunnitellessani keskityin tarkasti niihin tehtäviin, joissa se toisi eniten hyötyä. Muissa WordPress ongelmissa halusin kuitenkin painottaa omaa oppimistani. Siksi koin mielekkäämmäksi etsiä ratkaisuja itse sisällönhallintaohjelman ohjeista. Tämä tapa on mielestäni tehokkaampi tapa syventää omaa osaamista.

## Tekoälyn valinta ja valinnan perustelu

- Minkä/mitkä tekoälyjärjestelmät (lisää myös versio) valitsit ja miksi?
  - valitsin yleiseen oikein kirjoittamiseen [Gemini 1.5 flash](https://gemini.google.com/app?hl=fi) sillä se on ilmainen ja verrattuna GPT malleihin se on tehokkaampi selityksissä ja etsimisessä.
    - [Gemma 2 9B -mallin](https://lmstudio.ai/model/gemma-2-9b) jos kyllästyin Geminin kontekstin unohteluun.
  - kuvien luontiin valitsin [Fooocus AI](https://github.com/lllyasviel/Fooocus) joka on rakennettu kokonaan käyttäen [Stable diffusion XL](https://stablediffusionxl.com) arkkitehtuuria ja käyttöliittymä on toteutettu käyttäen [Gradio](https://www.gradio.app) kirjastoa.
  - käänöksiin valitsin [DeepL Translate](https://www.deepl.com/en/translator) joka on tällä hetkellä oman kokemuksen mukaan paras kääntäjä.

## Tekoälyn käyttöönotto ja soveltaminen

- Miten käytit tekoälyä projektissasi?
- Esimerkki käytöstä täyte tekstiin
  - **Prompti:** Teen WordPress-sivuston nahkakäsityöharrastajalle. Sivustolle halutaan esittely omasta toiminnasta ja             työskentelytavoista. Lisäksi halutaan sivu, jossa kerrotaan suvun historiasta käsitöiden parissa. Verkkokaupassa myydään omia tekeleitä ja käytettyjä esineitä.
  Tarvitsisin apua etusivun tekstien laatimisessa.
  - **tulos:** **Perintöä nahassa**
    Olen [Nimesi], intohimoinen nahkatyöläinen, jonka juuret ulottuvat sukupolvien taakse. Valmistamani käsintehtyjä nahkatuotteita henkii perinteinen käsityötaito ja moderni design. Jokainen tuote on ainutlaatuinen taideteos, jossa yhdistyvät laadukkaat materiaalit ja huolellinen käsityö. Tutustu laajaan valikoimaamme ja löydä täydellinen nahkakumppanisi.

- kääntämisessä kopion tekstin vain Deepl alustaan ja kopion käännökseen tuloksen ja muokkasin sen sellaiseen muotoon kuin halusin

- kuva tuotokset
  - prompti: Kuva esittää ruskeaa nahkaista vyötä, joka on kierretty renkaaksi. Vyö on koristeltu kahdella tiheällä, kontrastivärisellä saumatuksella. Saumat ovat väriltään mustat ja niiden sisällä kulkee ohut oranssi saumanauha. Vyön pinta on sileä ja kiiltävä, ja sen väri on lämmin ja syvä ruskea. Valokuva on otettu mustalla taustalla, mikä korostaa vyön yksityiskohtia ja materiaalia.
  - tulos:

 <img src="./images/brown-belt.jpg" width="250px" height="250px">

 käytetty placeholderina tuotteelle.

- Mitä haasteita kohtasit ja miten ratkaisit ne?
- Välillä Gemini-malli unohti keskustelun kontekstin. Ratkaisin tämän lataamalla [Gemma 2 9B -mallin](https://lmstudio.ai/model/gemma-2-9b) [LM Studioon](https://lmstudio.ai). Tämä on keskikokoinen malli, jonka on kehittänyt Google käyttäen samaa tutkimusta ja teknologiaa kuin Gemini-malleissa. Rakensin LM Studiossa ympäristön, jossa annoin mallille jatkuvan kontekstiohjauksen. Näin pystyin välttämään tarpeen selittää asiaa aina uudelleen.

## Tulokset ja tulosten analyysi

- Mitä tuloksia saavutit tekoälyn avulla?
  - Olin tyytyväinen saatuihin tuloksiin, sillä en asettanut malleille liian korkeita odotuksia. Pyrin pitämään ohjeistukseni tarkkarajaisina ja pyyntöni yksinkertaisina, mikä osaltaan vähensi tehtävien monimutkaisuutta.

- Miten tekoälyn käyttö vaikutti projektiin kokonaisuudessaan?
  - Tekooälyn käyttö nopeutti työtä huomattavasti ja takasi sen että kielivaihtoehdot sivulla ovat paremmin kirjoitettu ja selkeämmät.

## Reflektio ja oma oppiminen

- Mitä opit tekoälyn käytöstä tässä projektissa?
  - Tekoälyjen käytön osalta projekti ei tarjonnut minulle uusia haasteita, sillä olin jo hallinnut aiheen perusteet.

- Mitä suosituksia antaisit muille opiskelijoille, jotka käyttävät tekoälyä
projekteissaan?
  - Syventykää mallien toimintaperiaatteisiin ja siihen, mikä tekee tehtäväkuvauksesta erinomaisen juuri tälle mallille. Koska mallit eivät vielä pysty lukemaan mieltä, on tärkeää antaa selkeät ja yksityiskohtaiset ohjeet. Harjoitelkaa mallinhallintaohjelmien käyttöä, jotta voitte räätälöidä mallien toimintaa tarpeidenne mukaan ja ymmärtää niiden vahvuudet ja heikkoudet. Ennen kuin käytätte mallia, tutkikaa huolellisesti, mihin tarkoitukseen se on suunniteltu, jotta saatte siitä parhaan hyödyn.

## Liitteet, lähteet ja linkit

- Koodinäytteet, kaaviot, linkit, kuvakaappaukset, …
Suositus kielimallin käyttöön

- [Gemini 1.5 flash](https://gemini.google.com/app?hl=fi) ilmainen ja verrattuna GPT malleihin se on tehokkaampi selityksissä ja etsimisessä.
- [DeepL](https://www.deepl.com/en/translator) DeepL AI on kehittynyt tekoälypalvelu, joka on erikoistunut kielten kääntämiseen. Se tunnetaan erityisesti korkealaatuisesta ja luonnollisen kuuloisesta käännöksestään, joka ylittää monien muiden konekäännöstyökalujen suorituskyvyn.
  - DeepL AI tarjoaa myös muita hyödyllisiä ominaisuuksia, kuten:
  - DeepL Write: Tämä työkalu auttaa sinua parantamaan kirjoitustaitojasi tarjoamalla ehdotuksia sanavalintoihin, lauseenrakenteisiin ja tyyliin.
  - DeepL Translate: Tämä on perinteinen konekäännöstyökalu, joka tukee useita kielipareja ja tarjoaa korkealaatuisia käännöksiä.
- [Fooocus AI](https://github.com/lllyasviel/Fooocus)
- [Gradio](https://www.gradio.app) Gradio on avoimen lähdekoodin Python-kirjasto, jonka avulla voit nopeasti rakentaa käyttäjäystävällisiä web-käyttöliittymiä tekoälymalleillesi.
- [Gemma 2 9B](https://lmstudio.ai/model/gemma-2-9b) Tämä on keskikokoinen malli, jonka on kehittänyt Google käyttäen samaa tutkimusta ja teknologiaa kuin Gemini-malleissa.
- [LM Studio](https://lmstudio.ai) Tekoälymallien hallinta järjestelmä.
- [Pinokio](https://pinokio.computer) Toinen tekoälyn halllinta ohjelma joka keskittyy kuva, video ja ääni tekoälyihin. En käyttänyt tässä projektissa mutta tämä on helpoin tapa saada Foocus AI käyttöön.
