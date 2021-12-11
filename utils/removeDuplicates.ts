
export const removeDuplicates = (array : any[]) => {
    return array.filter((value, index) =>  array.indexOf(value) ===  index)
}

