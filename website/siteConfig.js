const siteConfig = {
  title: 'easy-crypto',
  tagline:
    'An easier crypto API for Node.js',
  url: 'https://ryzokuken.github.io/easy-crypto',
  baseUrl: '/',
  projectName: 'easy-crypto',
  organizationName: 'ryzokuken',
  headerLinks: [
    { doc: 'installation', label: 'Docs' },
    { doc: 'hash', label: 'API' },
  ],
  headerIcon: 'img/nodejs.svg',
  footerIcon: 'img/nodejs.svg',
  favicon: 'img/favicon.png',
  colors: {
    primaryColor: '#333',
    secondaryColor: '#007000'
  },
  copyright: `Copyright © ${new Date().getFullYear()} Ujjwal Sharma`,
  highlight: {
    theme: 'default'
  },
  scripts: ['https://buttons.github.io/buttons.js'],
  onPageNav: 'separate',
  cleanUrl: true,
};

module.exports = siteConfig;
