export const apiResponse = ( success : boolean , message : string, data : unknown = null) => {
    return {
        success,
        message, 
        data,
    }
}