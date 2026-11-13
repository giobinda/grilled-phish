GP_LEARN_I18N.pt = {
  langLabel: 'Idioma',
  title: 'Como reconhecer um site falso',
  lead: 'Um guia de 5 minutos. Não é preciso saber nada de técnica.',

  whatH: '1. O que é “phishing”?',
  what: [
    'Phishing (pronuncia-se “fishing”, ou seja, “pescaria”) é quando criminosos fingem ser alguém em quem você confia, como o seu banco, os Correios, a Amazon, a Receita/Finanças ou um familiar, para fazer você <strong>clicar num link</strong> e depois <strong>digitar uma senha, o número do cartão ou um código</strong> num site falso.',
    'O site falso pode ser <strong>idêntico</strong> ao verdadeiro: mesmo logotipo, mesmas cores, mesmas páginas. Hoje copiar um site leva minutos, então a aparência de uma página não prova nada. <strong>A única coisa que um criminoso não consegue copiar é o endereço do site.</strong>',
  ],

  addrH: '2. Leia o endereço, não a página',
  addr: 'O endereço aparece no alto do navegador. O que importa é o <strong>nome logo antes da primeira “/” sozinha</strong>, junto com a sua terminação (<code>.com</code>, <code>.br</code>, <code>.pt</code>…). Tudo o que vem antes pode ser inventado por qualquer pessoa.',
  real: 'Verdadeiro',
  fake: 'Falso',
  fake1: 'Este site é <code>secure-login.net</code>. O “paypal.com” no início é só enfeite.',
  fake2: 'Palavras extras como “help”, “secure”, “login” ou “verify” são acrescentadas pelos golpistas, não pelo PayPal.',

  lettersH: '3. Letras parecidas',
  letters: 'Os golpistas trocam letras que parecem iguais, sobretudo em letra pequena ou com a vista cansada:',
  thFake: 'Falso', thReal: 'Verdadeiro', thTrick: 'O truque',
  tricks: [
    '“r” + “n” parecem um “m”',
    'o número um no lugar do “l”',
    'um zero no lugar do “o”',
    'dois “v” no lugar do “w”',
    'uma letra russa que parece um “p”',
  ],
  lettersAfter: 'A última é impossível de ver, mesmo com uma vista perfeita. Por isso o Grilled Phish confere as letras por você e destaca as que são diferentes.',

  signsH: '4. Sinais de alerta nas mensagens',
  signsIntro: 'Quase todos os golpes começam com um e-mail, um SMS, uma mensagem de WhatsApp ou uma ligação. Desconfie quando a mensagem:',
  signs: [
    '⏰ <strong>Apressa você</strong>: “em 24 horas”, “sua conta será encerrada”, “último aviso”.',
    '😨 <strong>Assusta você</strong>: cartão bloqueado, multa, pagamento suspeito, problema com a polícia.',
    '🎁 <strong>Promete algo</strong>: um prêmio, um reembolso, uma encomenda à espera de uma pequena taxa.',
    '🔑 <strong>Pede uma senha, o número do cartão ou um código</strong> recebido por SMS.',
    '👋 <strong>Vem de um “número novo”</strong>: “Oi mãe, perdi meu celular, pode pagar esta conta para mim?”',
    '🔗 <strong>Tem um link</strong> para “verificar”, “confirmar”, “desbloquear” ou “atualizar” algo.',
  ],

  rulesH: '5. Cinco regras que impedem quase todos os golpes',
  rules: [
    '<strong>Não use links de mensagens para entrar nas suas contas.</strong> Abra o aplicativo do banco, digite o endereço você mesmo ou use um favorito salvo antes.',
    '<strong>Nunca diga a ninguém um código recebido por SMS.</strong> Nem ao banco, nem à polícia, nem ao “suporte técnico”. Empresas de verdade nunca pedem isso.',
    '<strong>Desligue e ligue você.</strong> Se alguém ligar sobre o seu dinheiro, encerre a chamada e ligue para o número impresso no cartão ou no site oficial.',
    '<strong>Não tenha pressa.</strong> Bancos e repartições de verdade podem esperar uma hora. Só os golpistas têm pressa.',
    '<strong>Pergunte a alguém de confiança</strong> antes de pagar ou digitar uma senha se algo parecer estranho. Golpistas costumam dizer “não conte a ninguém”: isso já é um sinal de alerta.',
  ],

  gpH: '6. O que o Grilled Phish faz por você',
  gp: [
    '🟥 Coloca uma <strong>moldura vermelha</strong> nos links para sites falsos e os bloqueia.',
    '🔒 Trava os campos de senha em sites que fingem ser outro.',
    '🗓️ Avisa sobre sites criados nas últimas semanas (a maioria dos sites de golpe é novíssima).',
    '🔎 Mostra quais letras são diferentes do site verdadeiro.',
  ],
  gpNote: '<strong>Nenhuma ferramenta pega tudo.</strong> Um truque novo, ou um golpe num site verdadeiro que foi invadido, pode passar. As regras acima protegem você mesmo quando o Grilled Phish não consegue.',

  clickedH: '7. Já clicou ou digitou alguma coisa?',
  clickedIntro: 'Não tenha vergonha: isso acontece todos os dias com pessoas cuidadosas e inteligentes. Aja rápido:',
  clicked: [
    'Se deu dados do cartão ou do banco: <strong>ligue já para o seu banco</strong> pelo número do cartão e peça o bloqueio.',
    'Se digitou uma senha: <strong>troque-a</strong> no site verdadeiro e em todos os sites onde usava a mesma.',
    'Se instalou um programa ou deixou alguém “acessar” o seu computador: desligue a internet e peça a alguém de confiança ou a um técnico para verificar.',
    '<strong>Denuncie</strong> (veja abaixo). Isso ajuda a derrubar o site falso para todos.',
  ],

  practiceH: 'Pratique',
  practice: 'veja 8 e-mails com aparência real e decida quais são golpes. Grátis, sem cadastro.',

  moreH: 'Saiba mais em fontes oficiais',
  reportH: 'Denuncie um golpe',
  inEnglish: '(em inglês)',
  src: {
    cisa: 'CISA, a agência de cibersegurança dos Estados Unidos',
    ncsc: 'NCSC, o centro nacional de cibersegurança do Reino Unido',
    aarp: 'AARP: artigos e alertas para pessoas com mais de 50 anos',
    google: 'Denuncie um site falso ao Google, para que Chrome, Brave, Firefox e Safari avisem também outras pessoas',
    ftc: 'Estados Unidos: Federal Trade Commission',
    ncscReport: 'Reino Unido: encaminhe e-mails suspeitos para report@phishing.gov.uk e SMS para 7726',
  },
  local: {
    more: [
      { href: 'https://cartilha.cert.br/fasciculos/', label: 'Cartilha de Segurança para Internet — CERT.br', desc: 'Brasil: fascículos simples sobre golpes, senhas e segurança' },
      { href: 'https://www.cncs.gov.pt/', label: 'Centro Nacional de Cibersegurança', desc: 'Portugal: alertas e recomendações' },
    ],
    report: [],
  },
  disclaimer: 'Estes links levam a órgãos oficiais ou organizações sem fins lucrativos. O Grilled Phish não tem ligação com eles.',
};
