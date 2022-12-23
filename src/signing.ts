import { SignedXml, FileKeyInfo } from 'xml-crypto';
import { DOMParser } from 'xmldom';
import { select1, SelectedValue } from 'xpath';
import { readFileAsync } from './utils';

class CustomKeyInfoProvider extends FileKeyInfo {
  certBuffer: Buffer;

  constructor(cert: Buffer) {
    super();
    this.certBuffer = cert;
  }

  public getKey = function (): Buffer {
    return this.certBuffer;
  };
}

const getSigningStr = async (cert: Buffer = null): Promise<string | Buffer> => {
  let signingStr;

  if (!cert) {
    try {
      signingStr = await readFileAsync(`${__dirname}/certs/testKey.pem`);
    } catch (error) {
      throw new Error('Unable to read certificate');
    }
  } else {
    signingStr = cert;
  }

  return signingStr;
};

const getNodeByExpr = (expression: string, xml: string): SelectedValue => {
  const doc = new DOMParser().parseFromString(xml);
  return select1(`${expression}`, doc);
};

export const sign = async (
  xml: string, // expectina ticket xml arba identity xml templeitu
  nodeName: 'authenticationRequest' | 'authenticationDataRequest', // template referencas arba to arba to
  cert: Buffer = null // test certas
) => {
  const noNewLinesXml = xml.replace(/(\r\n|\n|\r)/gm, ''); // kadangi expectina string xml template, stripina new linus jeigu tokie butu
  const expression = `//*[local-name(.)='${nodeName}']`; // cia expression sukuria kuris veliau bus naudojamas reiksmei pareplacinti
  const sig = new SignedXml(); // sukuria signedxml generic objekta su "local-name" kuria veliau pakeisim

  sig.addReference( // sitas metodas panaudoja expressiona, kad rastu kur pakeisti referencus, cia metadata reikalinga jog signed xml atitiktu tai ko expectina viisp auth api
    expression,
    [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    'http://www.w3.org/2000/09/xmldsig#sha1'
  );

  sig.signingKey = await getSigningStr(cert); // i signedxml objekta uzsetina signingKey
  sig.computeSignature(noNewLinesXml); sitoj stadijoj signing objektas paruostas 1. xmlas suformuotas, expressionai suformuoti

  // cia padares console.log(sig.getSignedXml()) pamatytum tiksliai kaip atrodo tinkamai suformuotas ir uzsignintas xml'a kuri naudosi paduodamas i soap clienta
  console.log(sig.getSignedXml());
  return sig.getSignedXml();
};

export const validate = async (xml: string, cert: Buffer = null) => {
  const expression = `//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']`;
  const signature = getNodeByExpr(expression, xml);
  const sig = new SignedXml();

  if (!cert) {
    sig.keyInfoProvider = new FileKeyInfo(`${__dirname}/certs/testCert.pem`);
  } else {
    sig.keyInfoProvider = new CustomKeyInfoProvider(cert);
  }

  sig.loadSignature(signature as Node);
  const res = sig.checkSignature(xml);

  return !!res;
};
