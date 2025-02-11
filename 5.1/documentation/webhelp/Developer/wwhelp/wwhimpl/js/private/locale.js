// Copyright (c) 2001-2003 Quadralay Corporation.  All rights reserved.
//

function  WWHJavaScriptMessages_Object()
{
  // Set default messages
  //
  WWHJavaScriptMessages_Set_en(this);

  this.fSetByLocale = WWHJavaScriptMessages_SetByLocale;
}

function  WWHJavaScriptMessages_SetByLocale(ParamLocale)
{
  var  LocaleFunction = null;


  // Match locale
  //
  if ((ParamLocale.length > 1) &&
      (eval("typeof(WWHJavaScriptMessages_Set_" + ParamLocale + ")") == "function"))
  {
    LocaleFunction = eval("WWHJavaScriptMessages_Set_" + ParamLocale);
  }
  else if ((ParamLocale.length > 1) &&
           (eval("typeof(WWHJavaScriptMessages_Set_" + ParamLocale.substring(0, 2) + ")") == "function"))
  {
    LocaleFunction = eval("WWHJavaScriptMessages_Set_" + ParamLocale.substring(0, 2));
  }

  // Default already set, only override if locale found
  //
  if (LocaleFunction != null)
  {
    LocaleFunction(this);
  }
}

function  WWHJavaScriptMessages_Set_de(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "Daten werden geladen...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "Inhalt";
  ParamMessages.mTabsIndexLabel     = "Index";
  ParamMessages.mTabsSearchLabel    = "Suchen";
  ParamMessages.mTabsFavoritesLabel = "Favoriten";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "Die aktuelle Seite wurde nicht im Inhalt gefunden.";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "Das von Ihnen gew\u00e4hlte Indexwort bzw. der gew\u00e4hlte Indexbegriff tritt in mehreren Dokumenten auf.";
  ParamMessages.mIndexSelectMessage2 = "W\u00e4hlen Sie ein Dokument aus.";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "Suchen";
  ParamMessages.mSearchScopeAllLabel       = "Alle verf\u00fcgbaren B\u00fccher";
  ParamMessages.mSearchDefaultMessage      = "Geben Sie das Wort bzw. die Worte ein, nach denen gesucht werden soll:";
  ParamMessages.mSearchSearchingMessage    = "(Suchen)";
  ParamMessages.mSearchNothingFoundMessage = "(keine Ergebnisse)";
  ParamMessages.mSearchRankLabel           = "Rang";
  ParamMessages.mSearchTitleLabel          = "Titel";
  ParamMessages.mSearchBookLabel           = "Buch";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "Hinzuf\u00fcgen";
  ParamMessages.mFavoritesRemoveButtonLabel  = "Entfernen";
  ParamMessages.mFavoritesDisplayButtonLabel = "Anzeigen";
  ParamMessages.mFavoritesCurrentPageLabel   = "Aktuelle Seite:";
  ParamMessages.mFavoritesListLabel          = "Seiten:";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "%s ausw\u00e4hlen";
  ParamMessages.mAccessibilityNavigationFrameName = "%s-Navigation";
  ParamMessages.mAccessibilityActiveTab           = "Registerkarte '%s' aktiv";
  ParamMessages.mAccessibilityInactiveTab         = "Zu Registerkarte '%s' umschalten";
  ParamMessages.mAccessibilityTOCBookExpanded     = "Buch '%s' erweitert";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "Buch '%s' zusammegezogen";
  ParamMessages.mAccessibilityTOCTopic            = "Thema '%s'";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "%s von %s";
  ParamMessages.mAccessibilityIndexEntry          = "Thema '%s', Buch '%s'";
  ParamMessages.mAccessibilityIndexSecondEntry    = "Thema '%s', Buch '%s', Link '%s'";
}

function  WWHJavaScriptMessages_Set_en(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "Loading data...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "Contents";
  ParamMessages.mTabsIndexLabel     = "Index";
  ParamMessages.mTabsSearchLabel    = "Search";
  ParamMessages.mTabsFavoritesLabel = "Favorites";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "The current page could not be found in the table of contents.";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "The index word or phrase you chose occurs in multiple documents.";
  ParamMessages.mIndexSelectMessage2 = "Please choose one.";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "Go!";
  ParamMessages.mSearchScopeAllLabel       = "All Available Books";
  ParamMessages.mSearchDefaultMessage      = "Type in the word(s) to search for. You can use an asterisk (*) as a wildcard character (e.g., 802.* or *queue*). To search for a phrase, enclose it in quotation marks (e.g., \"802.11 MAC\").";
  ParamMessages.mSearchSearchingMessage    = "(searching)";
  ParamMessages.mSearchNothingFoundMessage = "(no results)";
  ParamMessages.mSearchRankLabel           = "Rank";
  ParamMessages.mSearchTitleLabel          = "Title";
  ParamMessages.mSearchBookLabel           = "Book";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "Add";
  ParamMessages.mFavoritesRemoveButtonLabel  = "Remove";
  ParamMessages.mFavoritesDisplayButtonLabel = "Display";
  ParamMessages.mFavoritesCurrentPageLabel   = "Current page:";
  ParamMessages.mFavoritesListLabel          = "Pages:";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "Select %s";
  ParamMessages.mAccessibilityNavigationFrameName = "%s navigation";
  ParamMessages.mAccessibilityActiveTab           = "%s tab is active";
  ParamMessages.mAccessibilityInactiveTab         = "Switch to %s tab";
  ParamMessages.mAccessibilityTOCBookExpanded     = "Book %s expanded";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "Book %s collapsed";
  ParamMessages.mAccessibilityTOCTopic            = "Topic %s";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "%s of %s";
  ParamMessages.mAccessibilityIndexEntry          = "Topic %s of Book %s";
  ParamMessages.mAccessibilityIndexSecondEntry    = "Topic %s of Book %s link %s";
}

function  WWHJavaScriptMessages_Set_es(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "Cargando datos...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "Contenido";
  ParamMessages.mTabsIndexLabel     = "\u00cdndice";
  ParamMessages.mTabsSearchLabel    = "Buscar";
  ParamMessages.mTabsFavoritesLabel = "Favoritos";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "Esta p\u00e1gina no se encontr\u00f3 en el \u00edndice de contenidos.";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "La frase o palabra del \u00edndice elegida aparece en varios documentos.";
  ParamMessages.mIndexSelectMessage2 = "Elija uno.";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "Ir";
  ParamMessages.mSearchScopeAllLabel       = "Todos los libros disponibles";
  ParamMessages.mSearchDefaultMessage      = "Escriba las palabras que desee buscar:";
  ParamMessages.mSearchSearchingMessage    = "(buscando)";
  ParamMessages.mSearchNothingFoundMessage = "(ning\u00fan resultado)";
  ParamMessages.mSearchRankLabel           = "Clase";
  ParamMessages.mSearchTitleLabel          = "T\u00edtulo";
  ParamMessages.mSearchBookLabel           = "Libro";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "Agregar";
  ParamMessages.mFavoritesRemoveButtonLabel  = "Quitar";
  ParamMessages.mFavoritesDisplayButtonLabel = "Mostrar";
  ParamMessages.mFavoritesCurrentPageLabel   = "P\u00e1gina actual:";
  ParamMessages.mFavoritesListLabel          = "P\u00e1ginas:";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "Seleccione %s";
  ParamMessages.mAccessibilityNavigationFrameName = "Navegaci\u00f3n %s";
  ParamMessages.mAccessibilityActiveTab           = "La ficha %s est\u00e1 activa";
  ParamMessages.mAccessibilityInactiveTab         = "Cambie a la ficha %s";
  ParamMessages.mAccessibilityTOCBookExpanded     = "El libro %s est\u00e1 expandido";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "El libro %s est\u00e1 contra\u00eddo";
  ParamMessages.mAccessibilityTOCTopic            = "Tema %s";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "%s de %s";
  ParamMessages.mAccessibilityIndexEntry          = "Tema %s del libro %s";
  ParamMessages.mAccessibilityIndexSecondEntry    = "Tema %s del libro %s v\u00ednculo %s";
}

function  WWHJavaScriptMessages_Set_fr(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "Chargement des donn\u00e9es...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "Table des mati\u00e8res";
  ParamMessages.mTabsIndexLabel     = "Index";
  ParamMessages.mTabsSearchLabel    = "Rechercher";
  ParamMessages.mTabsFavoritesLabel = "Favoris";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "Page introuvable dans la table des mati\u00e8res.";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "Le terme ou l'expression d'index que vous avez choisis apparaissent dans plusieurs documents.";
  ParamMessages.mIndexSelectMessage2 = "S\u00e9lectionnez-en un.";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "Lancer";
  ParamMessages.mSearchScopeAllLabel       = "Tous les livres disponibles";
  ParamMessages.mSearchDefaultMessage      = "Saisissez un ou plusieurs mots cl\u00e9s\u00a0:";
  ParamMessages.mSearchSearchingMessage    = "(recherche en cours)";
  ParamMessages.mSearchNothingFoundMessage = "(aucun r\u00e9sultat)";
  ParamMessages.mSearchRankLabel           = "Pertinence";
  ParamMessages.mSearchTitleLabel          = "Titre";
  ParamMessages.mSearchBookLabel           = "Livre";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "Ajouter";
  ParamMessages.mFavoritesRemoveButtonLabel  = "Supprimer";
  ParamMessages.mFavoritesDisplayButtonLabel = "Afficher";
  ParamMessages.mFavoritesCurrentPageLabel   = "Page courante\u00a0:";
  ParamMessages.mFavoritesListLabel          = "Pages\u00a0:";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "S\u00e9lectionner %s";
  ParamMessages.mAccessibilityNavigationFrameName = "Navigation %s";
  ParamMessages.mAccessibilityActiveTab           = "L'onglet %s est actif";
  ParamMessages.mAccessibilityInactiveTab         = "Placez-vous sous l'onglet %s";
  ParamMessages.mAccessibilityTOCBookExpanded     = "Livre %s \u00e9tendu";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "Livre %s r\u00e9duit";
  ParamMessages.mAccessibilityTOCTopic            = "Rubrique %s";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "%s/%s";
  ParamMessages.mAccessibilityIndexEntry          = "Rubrique %s du livre %s";
  ParamMessages.mAccessibilityIndexSecondEntry    = "Rubrique %s du lien %s du livre %s";
}

function  WWHJavaScriptMessages_Set_it(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "Caricamento dati in corso...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "Contenuto";
  ParamMessages.mTabsIndexLabel     = "Indice";
  ParamMessages.mTabsSearchLabel    = "Cerca";
  ParamMessages.mTabsFavoritesLabel = "Preferiti";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "La pagina corrente non \u00e8 stata trovata nel Sommario.";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "La parola o la frase cercata nell'indice \u00e8 presente in pi\u00f9 documenti.";
  ParamMessages.mIndexSelectMessage2 = "Sceglierne uno.";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "Vai!";
  ParamMessages.mSearchScopeAllLabel       = "Tutti i libri disponibili";
  ParamMessages.mSearchDefaultMessage      = "Digitare le parole da cercare:";
  ParamMessages.mSearchSearchingMessage    = "(ricerca in corso)";
  ParamMessages.mSearchNothingFoundMessage = "(nessun risultato)";
  ParamMessages.mSearchRankLabel           = "Classe";
  ParamMessages.mSearchTitleLabel          = "Titolo";
  ParamMessages.mSearchBookLabel           = "Libro";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "Aggiungi";
  ParamMessages.mFavoritesRemoveButtonLabel  = "Rimuovi";
  ParamMessages.mFavoritesDisplayButtonLabel = "Visualizza";
  ParamMessages.mFavoritesCurrentPageLabel   = "Pagina corrente:";
  ParamMessages.mFavoritesListLabel          = "Pagine:";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "Seleziona %s";
  ParamMessages.mAccessibilityNavigationFrameName = "Navigazione %s";
  ParamMessages.mAccessibilityActiveTab           = "La scheda %s \u00e8 attiva";
  ParamMessages.mAccessibilityInactiveTab         = "Passa alla scheda %s";
  ParamMessages.mAccessibilityTOCBookExpanded     = "Libro %s espanso";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "Libro %s compresso";
  ParamMessages.mAccessibilityTOCTopic            = "Argomento %s";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "%s di %s";
  ParamMessages.mAccessibilityIndexEntry          = "Argomento %s del libro %s";
  ParamMessages.mAccessibilityIndexSecondEntry    = "Argomento %s del libro %s collegamento %s";
}

function  WWHJavaScriptMessages_Set_ja(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "?????????????";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "??";
  ParamMessages.mTabsIndexLabel     = "??";
  ParamMessages.mTabsSearchLabel    = "??";
  ParamMessages.mTabsFavoritesLabel = "?????";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "??????????????????????";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "???????????????????????????????????";
  ParamMessages.mIndexSelectMessage2 = "1 ??????????????????";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "??";
  ParamMessages.mSearchScopeAllLabel       = "????????????";
  ParamMessages.mSearchDefaultMessage      = "?????:";
  ParamMessages.mSearchSearchingMessage    = "(???)";
  ParamMessages.mSearchNothingFoundMessage = "(????)";
  ParamMessages.mSearchRankLabel           = "???";
  ParamMessages.mSearchTitleLabel          = "????";
  ParamMessages.mSearchBookLabel           = "???";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "??";
  ParamMessages.mFavoritesRemoveButtonLabel  = "??";
  ParamMessages.mFavoritesDisplayButtonLabel = "??";
  ParamMessages.mFavoritesCurrentPageLabel   = "??????:";
  ParamMessages.mFavoritesListLabel          = "???:";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "%s ???";
  ParamMessages.mAccessibilityNavigationFrameName = "%s ???????";
  ParamMessages.mAccessibilityActiveTab           = "%s ???????????";
  ParamMessages.mAccessibilityInactiveTab         = "%s ????????";
  ParamMessages.mAccessibilityTOCBookExpanded     = "JA ??? %s ???????????";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "JA ??? %s ???????????";
  ParamMessages.mAccessibilityTOCTopic            = "JA ???? %s";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "JA %s/%s";
  ParamMessages.mAccessibilityIndexEntry          = "JA ???? %s/??? %s";
  ParamMessages.mAccessibilityIndexSecondEntry    = "JA ???? %s/??? %s ??? %s";
}

function  WWHJavaScriptMessages_Set_ko(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "??? ?? ?...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "???";
  ParamMessages.mTabsIndexLabel     = "??";
  ParamMessages.mTabsSearchLabel    = "??";
  ParamMessages.mTabsFavoritesLabel = "?? ??";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "???? ?? ???? ?? ? ????.";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "??? ?? ?? ?? ??? ?? ??? ?????.";
  ParamMessages.mIndexSelectMessage2 = "??? ??????.";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "??";
  ParamMessages.mSearchScopeAllLabel       = "?? ?";
  ParamMessages.mSearchDefaultMessage      = "???? ??????.";
  ParamMessages.mSearchSearchingMessage    = "(?? ?)";
  ParamMessages.mSearchNothingFoundMessage = "(?? ??)";
  ParamMessages.mSearchRankLabel           = "??";
  ParamMessages.mSearchTitleLabel          = "??";
  ParamMessages.mSearchBookLabel           = "?";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "??";
  ParamMessages.mFavoritesRemoveButtonLabel  = "??";
  ParamMessages.mFavoritesDisplayButtonLabel = "??";
  ParamMessages.mFavoritesCurrentPageLabel   = "?? ???:";
  ParamMessages.mFavoritesListLabel          = "???:";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "%s ??";
  ParamMessages.mAccessibilityNavigationFrameName = "%s ?????";
  ParamMessages.mAccessibilityActiveTab           = "%s ? ??";
  ParamMessages.mAccessibilityInactiveTab         = "%s ? ??";
  ParamMessages.mAccessibilityTOCBookExpanded     = "%s ? ??";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "%s ? ??";
  ParamMessages.mAccessibilityTOCTopic            = "%s ??";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "%s? %s";
  ParamMessages.mAccessibilityIndexEntry          = "%s ?? %s ??";
  ParamMessages.mAccessibilityIndexSecondEntry    = "%s ? %s ??? %s ??";
}

function  WWHJavaScriptMessages_Set_pt(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "Carregando dados...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "Conte\u00fado";
  ParamMessages.mTabsIndexLabel     = "\u00cdndice remissivo";
  ParamMessages.mTabsSearchLabel    = "Procurar";
  ParamMessages.mTabsFavoritesLabel = "Favoritos";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "A p\u00e1gina atual n\u00e3o p\u00f4de ser encontrada no Sum\u00e1rio.";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "A palavra ou frase escolhida no \u00edndice remissivo consta de mais de um documento.";
  ParamMessages.mIndexSelectMessage2 = "Escolha um.";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "Prosseguir";
  ParamMessages.mSearchScopeAllLabel       = "Todos os livros dispon\u00edveis";
  ParamMessages.mSearchDefaultMessage      = "Digite a(s) palavra(s) a ser(em) procurada(s):";
  ParamMessages.mSearchSearchingMessage    = "(procurando)";
  ParamMessages.mSearchNothingFoundMessage = "(nenhum resultado)";
  ParamMessages.mSearchRankLabel           = "Escopo";
  ParamMessages.mSearchTitleLabel          = "T\u00edtulo";
  ParamMessages.mSearchBookLabel           = "Livro";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "Adicionar";
  ParamMessages.mFavoritesRemoveButtonLabel  = "Remover";
  ParamMessages.mFavoritesDisplayButtonLabel = "Mostrar";
  ParamMessages.mFavoritesCurrentPageLabel   = "P\u00e1gina atual:";
  ParamMessages.mFavoritesListLabel          = "P\u00e1ginas:";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "Selecione %s";
  ParamMessages.mAccessibilityNavigationFrameName = "navega\u00e7\u00e3o %s";
  ParamMessages.mAccessibilityActiveTab           = "A guia %s est\u00e1 ativa";
  ParamMessages.mAccessibilityInactiveTab         = "Alterne para a guia %s";
  ParamMessages.mAccessibilityTOCBookExpanded     = "Livro %s expandido";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "Livro %s recolhido";
  ParamMessages.mAccessibilityTOCTopic            = "T\u00f3pico %s";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "%s de %s";
  ParamMessages.mAccessibilityIndexEntry          = "T\u00f3pico %s do livro %s";
  ParamMessages.mAccessibilityIndexSecondEntry    = "T\u00f3pico %s do livro %s, link %s";
}

function  WWHJavaScriptMessages_Set_sv(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "L\u00e4ser in data...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "Inneh\u00e5ll";
  ParamMessages.mTabsIndexLabel     = "Index";
  ParamMessages.mTabsSearchLabel    = "S\u00f6k";
  ParamMessages.mTabsFavoritesLabel = "Favoriter";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "Det gick inte att hitta den aktuella sidan i inneh\u00e5llsf\u00f6rteckningen.";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "Det indexord eller den fras du valde f\u00f6rekommer i flera dokument.";
  ParamMessages.mIndexSelectMessage2 = "V\u00e4lj ett dokument.";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "Visa";
  ParamMessages.mSearchScopeAllLabel       = "Alla tillg\u00e4ngliga b\u00f6cker";
  ParamMessages.mSearchDefaultMessage      = "Ange de ord du vill s\u00f6ka efter:";
  ParamMessages.mSearchSearchingMessage    = "(s\u00f6ker)";
  ParamMessages.mSearchNothingFoundMessage = "(inga resultat)";
  ParamMessages.mSearchRankLabel           = "Relevans";
  ParamMessages.mSearchTitleLabel          = "Rubrik";
  ParamMessages.mSearchBookLabel           = "Bok";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "L\u00e4gg till";
  ParamMessages.mFavoritesRemoveButtonLabel  = "Ta bort";
  ParamMessages.mFavoritesDisplayButtonLabel = "Visa";
  ParamMessages.mFavoritesCurrentPageLabel   = "Aktuell sida:";
  ParamMessages.mFavoritesListLabel          = "Sidor:";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "V\u00e4lj %s";
  ParamMessages.mAccessibilityNavigationFrameName = "%s-navigering";
  ParamMessages.mAccessibilityActiveTab           = "Fliken %s \u00e4r aktiv";
  ParamMessages.mAccessibilityInactiveTab         = "V\u00e4xla till fliken %s";
  ParamMessages.mAccessibilityTOCBookExpanded     = "Boken %s maximerades";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "Boken %s minimerades";
  ParamMessages.mAccessibilityTOCTopic            = "Avsnitt %s";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "%s av %s";
  ParamMessages.mAccessibilityIndexEntry          = "Avsnitt %s i boken %s";
  ParamMessages.mAccessibilityIndexSecondEntry    = "Avsnitt %s i boken %s, l\u00e4nk %s";
}

function  WWHJavaScriptMessages_Set_zh(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "??????...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "??";
  ParamMessages.mTabsIndexLabel     = "??";
  ParamMessages.mTabsSearchLabel    = "??";
  ParamMessages.mTabsFavoritesLabel = "???";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "??????????";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "????????????????";
  ParamMessages.mIndexSelectMessage2 = "??????";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "???";
  ParamMessages.mSearchScopeAllLabel       = "????";
  ParamMessages.mSearchDefaultMessage      = "?????????";
  ParamMessages.mSearchSearchingMessage    = "????";
  ParamMessages.mSearchNothingFoundMessage = "?????";
  ParamMessages.mSearchRankLabel           = "??";
  ParamMessages.mSearchTitleLabel          = "??";
  ParamMessages.mSearchBookLabel           = "??";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "??";
  ParamMessages.mFavoritesRemoveButtonLabel  = "??";
  ParamMessages.mFavoritesDisplayButtonLabel = "??";
  ParamMessages.mFavoritesCurrentPageLabel   = "????";
  ParamMessages.mFavoritesListLabel          = "??";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "?? %s";
  ParamMessages.mAccessibilityNavigationFrameName = "%s ??";
  ParamMessages.mAccessibilityActiveTab           = "%s ?????";
  ParamMessages.mAccessibilityInactiveTab         = "??? %s ??";
  ParamMessages.mAccessibilityTOCBookExpanded     = "??? %s ?";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "??? %s ?";
  ParamMessages.mAccessibilityTOCTopic            = "%s ??";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "? %s?? %s";
  ParamMessages.mAccessibilityIndexEntry          = "%s ??? %s ??";
  ParamMessages.mAccessibilityIndexSecondEntry    = "%s ?? %s ???? %s ??";
}

function  WWHJavaScriptMessages_Set_zh_tw(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "????...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "??";
  ParamMessages.mTabsIndexLabel     = "??";
  ParamMessages.mTabsSearchLabel    = "??";
  ParamMessages.mTabsFavoritesLabel = "??";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "???????????";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "??????????????????";
  ParamMessages.mIndexSelectMessage2 = "????????";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "???";
  ParamMessages.mSearchScopeAllLabel       = "??????";
  ParamMessages.mSearchDefaultMessage      = "????????";
  ParamMessages.mSearchSearchingMessage    = "(???)";
  ParamMessages.mSearchNothingFoundMessage = "(????)";
  ParamMessages.mSearchRankLabel           = "???";
  ParamMessages.mSearchTitleLabel          = "??";
  ParamMessages.mSearchBookLabel           = "??";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "??";
  ParamMessages.mFavoritesRemoveButtonLabel  = "??";
  ParamMessages.mFavoritesDisplayButtonLabel = "??";
  ParamMessages.mFavoritesCurrentPageLabel   = "?????";
  ParamMessages.mFavoritesListLabel          = "???";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "?? %s";
  ParamMessages.mAccessibilityNavigationFrameName = "%s ??";
  ParamMessages.mAccessibilityActiveTab           = "%s ?????";
  ParamMessages.mAccessibilityInactiveTab         = "??? %s ??";
  ParamMessages.mAccessibilityTOCBookExpanded     = "?? %s ???";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "?? %s ???";
  ParamMessages.mAccessibilityTOCTopic            = "?? %s";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "%s / %s";
  ParamMessages.mAccessibilityIndexEntry          = "?? %s??? %s";
  ParamMessages.mAccessibilityIndexSecondEntry    = "?? %s??? %s ?? %s";
}

function  WWHJavaScriptMessages_Set_ru(ParamMessages)
{
  // Initialization Messages
  //
  ParamMessages.mInitializingMessage = "??????????? ???????? ??????...";

  // Tab Labels
  //
  ParamMessages.mTabsTOCLabel       = "??????????";
  ParamMessages.mTabsIndexLabel     = "?????????";
  ParamMessages.mTabsSearchLabel    = "?????";
  ParamMessages.mTabsFavoritesLabel = "?????????";

  // TOC Messages
  //
  ParamMessages.mTOCFileNotFoundMessage = "?????????? ????? ? ?????????? ??????? ????????.";

  // Index Messages
  //
  ParamMessages.mIndexSelectMessage1 = "????????? ????? (?????) ?? ????????? ?????????? ? ?????????? ??????????.";
  ParamMessages.mIndexSelectMessage2 = "???????? ???? ????????.";

  // Search Messages
  //
  ParamMessages.mSearchButtonLabel         = "??????";
  ParamMessages.mSearchScopeAllLabel       = "??? ????????? ????";
  ParamMessages.mSearchDefaultMessage      = "??????? ????? (?????) ??? ??????:";
  ParamMessages.mSearchSearchingMessage    = "(?????)";
  ParamMessages.mSearchNothingFoundMessage = "(??? ???????????)";
  ParamMessages.mSearchRankLabel           = "????";
  ParamMessages.mSearchTitleLabel          = "?????????";
  ParamMessages.mSearchBookLabel           = "???";

  // Favorites Messages
  //
  ParamMessages.mFavoritesAddButtonLabel     = "????????";
  ParamMessages.mFavoritesRemoveButtonLabel  = "???????";
  ParamMessages.mFavoritesDisplayButtonLabel = "????????";
  ParamMessages.mFavoritesCurrentPageLabel   = "??????? ????????:";
  ParamMessages.mFavoritesListLabel          = "????????:";

  // Accessibility Messages
  //
  ParamMessages.mAccessibilityTabsFrameName       = "??????? %s";
  ParamMessages.mAccessibilityNavigationFrameName = "????????? %s";
  ParamMessages.mAccessibilityActiveTab           = "??????? %s ???????";
  ParamMessages.mAccessibilityInactiveTab         = "??????? ?? ??????? %s";
  ParamMessages.mAccessibilityTOCBookExpanded     = "??? %s ?????????";
  ParamMessages.mAccessibilityTOCBookCollapsed    = "??? %s ???????";
  ParamMessages.mAccessibilityTOCTopic            = "?????? %s";
  ParamMessages.mAccessibilityTOCOneOfTotal       = "%s ?? %s";
  ParamMessages.mAccessibilityIndexEntry          = "?????? %s ? ???? %s";
  ParamMessages.mAccessibilityIndexSecondEntry    = "??????? %s ?? ?????? %s ? ???? %";
}
