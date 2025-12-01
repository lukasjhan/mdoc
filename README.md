<p align="center">
  <picture>
   <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656578320/animo-logo-light-no-text_ok9auy.svg">
   <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656578320/animo-logo-dark-no-text_fqqdq9.svg">
   <img alt="Animo Logo" height="250px" />
  </picture>
</p>

<h1 align="center" ><b>mDOC and mDL - TypeScript</b></h1>

[ISO 18013-5](https://www.iso.org/standard/69084.html) defines mDL (mobile Driver’s Licenses): an ISO standard for digital driver licenses.

This is a JavaScript library for Node.JS, browers and React Native to issue and verify mDL [CBOR encoded](https://cbor.io/) documents in accordance with **ISO 18013-7 (draft's date: 2024-03-12)**.

<h4 align="center">Powered by &nbsp; 
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656579715/animo-logo-light-text_cma2yo.svg">
    <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656579715/animo-logo-dark-text_uccvqa.svg">
    <img alt="Animo Logo" height="12px" />
  </picture>
</h4><br>

<p align="center">
  <a href="https://typescriptlang.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg" />
  </a>
  <a href="https://www.npmjs.com/package/@animo-id/mdoc">
    <img src="https://img.shields.io/npm/v/@animo-id/mdoc" />
  </a>
</p>

<p align="center">
  <a href="#installation">Installation</a> 
  &nbsp;|&nbsp;
  <a href="#contributing">Contributing</a>
  &nbsp;|&nbsp;
  <a href="#license">License</a>
  &nbsp;|&nbsp;
  <a href="#credits">Credits</a>
</p>

## Installation

```bash
npm i @animo-id/mdoc
```


## Contributing

Is there something you'd like to fix or add? Great, we love community
contributions! To get involved, please follow our [contribution guidelines](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License Version 2.0 (Apache-2.0).

## Credits

Thanks to:

- [auth0/mdl](https://github.com/auth0-lab/mdl) for the mdl implementation on which this repository is based.
- [auer-martin](https://github.com/auer-martin) for removing node.js dependencies and providing a pluggable crypto interface
