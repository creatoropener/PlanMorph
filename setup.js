import 'dotenv/config';
import fs from 'fs';
import * as pp from './paypal.js';

const p = await pp.createProduct();
const [standard, basic, retention] = await Promise.all([
  pp.createPlan(p.id, 'Standard', '10.00'),
  pp.createPlan(p.id, 'Basic', '5.00'),
  pp.createPlan(p.id, 'Standard - 3 months 30% off', '10.00', '7.00'),
]);
fs.writeFileSync('plans.json', JSON.stringify({ standard: standard.id, basic: basic.id, retention: retention.id }, null, 2));
console.log('Created product + plans -> plans.json');
