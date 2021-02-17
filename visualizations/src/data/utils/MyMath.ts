 

export default class MyMath {

    // https://stackoverflow.com/a/17411276
    public static rotateAroundPoint(cx:number, cy:number, x:number, y:number, angle:number) {
        const radians = (Math.PI / 180) * -angle,
            cos = Math.cos(radians),
            sin = Math.sin(radians),
            nx = (cos * (x - cx)) + (sin * (y - cy)) + cx,
            ny = (cos * (y - cy)) - (sin * (x - cx)) + cy;
            
        return {x : nx, y: ny};
    }
    
} 
    
      
