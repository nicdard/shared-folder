% Document class for typesetting Bachelor/Master/Semester projects.
% Example:
%
% \documentclass[E]{BAMASA}                             % E = english titles
% \renewcommand{\asst}{Martin Hirt}                   % YOUR name
% \begin{document}
% \SA{October 23, 2001}{February 15, 2001}{Juraj Skripsky}%
%    {Minimal Models for Receipt-Free Voting}         % \SA or \DA or \MA
%
% \intro                                              % make title
% blah
%
% \desc                                               % make title
% blah
%
% \tasks                                              % make title
% blah
%
% \grading                                            % infotext for MA
% \blah                                               % infotext for SA
% 
%
%
% \refs                                               % references
%
% \bibliography{mpc}                                  % your bib files
%
% \end{document}

\NeedsTeXFormat{LaTeX2e}[1995/12/01]
\ProvidesClass{BAMASA}
              [2020/03/20 v0.9
 BAMASA document class]
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{article}}
\let\eng=0
\let\newstyle=1
\DeclareOption{E}{\let\eng=1}
\DeclareOption{D}{\let\eng=0}
\DeclareOption{old}{\let\newstyle=0}
\DeclareOption{new}{\let\newstyle=1}
\ProcessOptions
\LoadClass[11pt]{article}

\topmargin=-.5cm\headheight=0pt\headsep=0pt\voffset=0pt\textheight=23.5cm
\textwidth=16cm\oddsidemargin=-.2cm
\parsep=0pt\parindent=0pt

%\renewenvironment{thebibliography}[1]
%     {\section*{\refname
%        \@mkboth{\MakeUppercase\refname}{\MakeUppercase\refname}}%
%      \list{\@biblabel{\@arabic\c@enumiv}}%
%           {\settowidth\labelwidth{\@biblabel{#1}}%
%            \leftmargin\labelwidth
%            \advance\leftmargin\labelsep
%            \itemsep=0pt
%            \usecounter{enumiv}%
%            \let\p@enumiv\@empty
%            \renewcommand\theenumiv{\@arabic\c@enumiv}}%
%      \sloppy
%      \clubpenalty4000
%      \@clubpenalty \clubpenalty
%      \widowpenalty4000%
%      \sfcode`\.\@m}
%     {\def\@noitemerr
%       {\@latex@warning{Empty `thebibliography' environment}}%
%      \endlist}


\def\prof{Prof.~Dr.~Kenny Paterson}
\def\asst{}

%
% English version
%
\if1\eng

\def\institute{Institute of Information Security}

\def\group{Applied Cryptography Group}

\def\sem{Semester Project} 

\def\bap{Bachelor's Project} 

\def\map{Master's Project} 

\def\for{for} 

\def\beg{Start} 

\def\ende{End}

\def\duration{Duration} 

\def\intro{\section{Introduction}}

\def\desc{\section{Description}} 

\def\tasks{\section{Tasks}
The project includes the following work packages (WP) (extensions possible):
}

\newcounter{wpcounter}[section]
\newenvironment{workpackage}[2][]{\refstepcounter{wpcounter}\subsection*{WP\thewpcounter: #2}}{}

\def\gradingMA{\section{Grading of the Thesis}
  
  The Master's project encompasses independent scientific research, writing
  a Master's thesis, and giving two presentations (a mid-way presentation and a final presentation). The evaluation of the
  thesis takes into account the quality of the results (understanding of
  the subject, contributed ideas, correctness) and the quality of the
  documentation (thesis and presentation).}
  

 % More instructions for the documentation and information about grading
 %criteria can be found in the enclosed leaflets.}

\def\gradingBA{\section{Grading of the Thesis}
  
  The Bachelor's project encompasses carrying out independent scientific work, writing
  a Bachelor's thesis, and giving a final presentation. The evaluation of the
  thesis takes into account the quality of the results (understanding of
  the subject, contributed ideas, correctness) and the quality of the
  documentation (thesis and presentation).}
  

 % More instructions for the documentation and information about grading
 %criteria can be found in the enclosed leaflets.}

\def\blah{The results have to be presented in a talk by the end of
    the project. Some instructions about the documentation can be found in
    the enclosed leaflet.}

\def\refs{} 


%
% German version
%
\else

\usepackage[german]{babel} 

\def\institute{Institut f{\"u}r Informationssicherheit}

\def\group{Applied Cryptography Group}

\def\sem{Semesterarbeit} 

\def\bap{Bachelorarbeit} 

\def\map{Masterarbeit}

\def\for{f"ur} 

\def\For{F"ur} 

\def\beg{Beginn} 

\def\ende{Abgabe}

\def\duration{Dauer} 

\def\intro{\section{Einleitung}}

\def\desc{\section{Beschreibung}} 

\def\tasks{\section{Aufgabenstellung}
Das Projekt beinhaltet folgende Aufgaben (Erweiterungen m\"{o}glich):
}

\def\grading{\section{Bewertung der Arbeit}
  
  Die Masterarbeit umfasst eine eigenst\"{a}ndige wissenschaftliche
  Untersuchung, einen schriftlichen Bericht und eine Pr\"{a}sentation. Bei
  der Benotung der Masterarbeit werden die erreichten Resultate
  (Verst\"{a}ndnis, Ideen, konkrete Resultate) und die Dokumentation der
  Arbeit (Darstellung der Resultate und der breiteren theoretischen
  Zusammenh\"{a}nge im Bericht und in der Pr\"{a}sentation) im gleichen
  Masse bewertet.
  
 
  Anhaltspunkte f\"{u}r die Dokumentation und Informationen zu den
  Bewertungskriterien gibt das beiliegende Merkblatt.  }

\def\blah{Gegen Ende soll die Arbeit zudem in einem Vortrag pr\"asentiert
  werden. Anhaltspunkte f\"ur die Dokumentation gibt das beiliegende
  Merkblatt.}

\def\refs{} \fi
  
\usepackage{times,helvet,graphicx}

\pagestyle{empty}


%- main macro ----------------------------------------------------------

\if1\newstyle
\newcommand{\proj}[5][PROJECT]{%
  \noindent
  \begin{tabular}[]{@{}l@{}}  % [] -> [t]
%    \mbox{}\\[-2.4ex]
    \includegraphics[scale=0.25]{ethlogo}
  \end{tabular}%
  \hfill{\sffamily%
    \begin{tabular}[]{@{}l@{}}  % [] -> [t]
      {\bfseries\institute}\\[.5ex]
      {\bfseries\group}\\[.5ex]
      \prof\\[.5ex]
      \asst
    \end{tabular}
  }

  \bigskip

  {\large\bf #1 \for{} #4}\\[.5ex]
   #2\ \ --\ \ #3\\

  \bigskip

  \centerline{\LARGE\bf #5}

  \bigskip
}
\else
\newcommand{\proj}[5][PROJECT]{%
  \vspace*{1cm}
  \noindent
  \begin{picture}(0,0)
    \put(0,0){\makebox(0,0)[lb]{\parbox{\linewidth}{%
          \rule{\linewidth}{.3pt} \\[1.5ex]
          \includegraphics{/pub/tetex/all/texmf/tex/latex/ETHmacros/ETHleft.ps}
          \hfill
          \includegraphics{/pub/tetex/all/texmf/tex/latex/ETHmacros/ETHright.ps}
          \\[-1ex]
          \rule{\linewidth}{.3pt}\\[0ex]}}}
  \end{picture}
  \begin{tabular}[t]{@{}l}
    \institute\\ \group\\ \prof\\ \asst
  \end{tabular}
  \hfill
  \begin{tabular}[t]{r@{}}
    \beg: #2\\
    \ende: #3
  \end{tabular}
  \par
  \begin{center}
  \LARGE\bf #1 \\[4mm]
  {\large \for{} #4}\\[10mm]
  #5
  \vspace{5mm}
\end{center}
}
\fi

%\SA{from}{to}{for}{title}
\newcommand{\SA}[5][\sem]{\proj[#1]{#2}{#3}{#4}{#5}}

%\DA{from}{to}{for}{title}
\newcommand{\BA}[5][\bap]{\proj[#1]{#2}{#3}{#4}{#5}}

%\MA{from}{to}{for}{title}
\newcommand{\MA}[5][\map]{\proj[#1]{#2}{#3}{#4}{#5}}


\bibliographystyle{alpha}
