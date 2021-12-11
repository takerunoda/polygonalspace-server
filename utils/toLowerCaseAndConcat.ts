export const toLowerCaseAndConcat = (item: any) => {
const x = item && item.toLowerCase();
const y = x && x.replace(/\s/g, '_')
    return y
}