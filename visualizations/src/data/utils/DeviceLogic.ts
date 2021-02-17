
export default class DeviceLogic {

    public static isLocalConnection ( connection:any ) : boolean {
        if ( connection && connection.info && connection.info.endpoint1 ) {
            if ( DeviceLogic.isLocalIP(connection.info.endpoint1.ip) && DeviceLogic.isLocalIP(connection.info.endpoint2.ip) ) {
                return true;
            }
        }

        return false;
    }

    public static isLocalIP ( ip:string ) {
        return ip.indexOf("192.168") >= 0;
    }
}