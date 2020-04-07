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
  xml: string,
  nodeName: 'authenticationRequest' | 'authenticationDataRequest',
  cert: Buffer = null
) => {
  const noNewLinesXml = xml.replace(/(\r\n|\n|\r)/gm, '');
  const expression = `//*[local-name(.)='${nodeName}']`;
  const sig = new SignedXml();

  sig.addReference(
    expression,
    [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    'http://www.w3.org/2000/09/xmldsig#sha1'
  );

  sig.signingKey = await getSigningStr(cert);
  sig.computeSignature(noNewLinesXml);
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
