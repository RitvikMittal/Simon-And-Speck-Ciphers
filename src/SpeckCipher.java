
import java.util.Arrays;

class SpeckCipher{
    Utilities.PKCS5Padding pad;
    private int sizeBits;
    private int sizeBytes;
    private byte[] input;
    private byte[] encryted;
    private byte[] keyInitial;
    private int keyWords;
    private int r=0;
    private long[] keys;
    private long mask;
    private int alpha;
    private int beta;
    SpeckCipher() {
        pad=new Utilities.PKCS5Padding();
    }
    void initialize(byte[] input,int blockSize,byte[] key,int mode)throws IllegalArgumentException{
        this.sizeBits=blockSize;
        this.alpha=8;
        this.beta=3;
        sizeBytes=sizeBits/8;
        pad.initialize(sizeBytes);
        keyInitial=key;
        keyWords=(key.length*2)/sizeBytes;
        boolean flag=((key.length*2)%sizeBytes==0);
        switch (sizeBits){
            case 32:
                mask=0x000000000000FFFFL;
                if(keyWords!=4||!flag){
                    throw new IllegalArgumentException();
                }else{
                    r=22;
                    alpha=7;
                    beta=2;
                }
                break;
            case 48:
                mask=0x0000000000FFFFFFL;
                if(flag) {
                    if (keyWords == 3) {
                        r = 22;
                    } else if (keyWords == 4) {
                        r = 23;
                    } else {
                        throw new IllegalArgumentException();
                    }
                }else{
                    throw new IllegalArgumentException();
                }
                break;
            case 64:
                mask=0x00000000FFFFFFFFL;
                if(flag) {
                    if (keyWords == 3) {
                        r = 26;
                    } else if (keyWords == 4) {
                        r = 27;
                    } else {
                        throw new IllegalArgumentException();
                    }
                }else{
                    throw new IllegalArgumentException();
                }
                break;
            case 96:
                mask=0x0000FFFFFFFFFFFFL;
                if(flag) {
                    if (keyWords == 2) {
                        r = 28;
                    } else if (keyWords == 3) {
                        r = 29;
                    } else {
                        throw new IllegalArgumentException();
                    }
                }else{
                    throw new IllegalArgumentException();
                }
                break;
            case 128:
                mask=0xFFFFFFFFFFFFFFFFL;
                if(flag) {
                    if (keyWords == 2) {
                        r = 32;
                    } else if (keyWords == 3) {
                        r = 33;
                    } else if(keyWords==4){
                        r=34;
                    } else {
                        throw new IllegalArgumentException();
                    }
                }else{
                    throw new IllegalArgumentException();
                }
                break;
            default:
                throw new IllegalArgumentException();
        }
        if(mode==0) {
            this.input = pad.addPKCS5Padding(input);
        }else{
            this.input=input;
        }
        makeKeys();
//        System.out.println(Arrays.toString(keys));
    }
    private void makeKeys(){
        keys=new long[r];
        keys[0]=Utilities.bytesToLong(keyInitial,(keyWords-1)*sizeBytes/2,sizeBytes/2);
        long[] l=new long[keyWords];
        for(int i=0;i<keyWords-1;i++){
            l[i]=Utilities.bytesToLong(keyInitial,(keyWords-i-2)*sizeBytes/2,sizeBytes/2);
        }
        for(int i=0;i<r-1;i++){
            int lset=(i+keyWords-1)%keyWords;
            l[lset]=(keys[i]+Utilities.rotateRight(l[i%keyWords],alpha,sizeBits/2))^i;
            l[lset]&=mask;
            keys[i+1]=Utilities.rotateLeft(keys[i],beta,sizeBits/2)^l[lset];
            keys[i+1]&=mask;
        }
    }
    byte[] encrypt(){
        byte[] out=new byte[input.length];
        int l=input.length/sizeBytes;
        for(int i=0;i<l;i++){
            long x=Utilities.bytesToLong(input,2*i*sizeBytes/2,sizeBytes/2);
            long y=Utilities.bytesToLong(input,(2*i+1)*sizeBytes/2,sizeBytes/2);
//            System.out.println(x+" "+y);
            for(int j=0;j<r;j++){
                x=(Utilities.rotateRight(x,alpha,sizeBits/2)+y);
                x^=keys[j];
                x&=mask;
                y=Utilities.rotateLeft(y,beta,sizeBits/2)^x;
                y&=mask;
            }
//            System.out.println(x+" "+y);
            Utilities.longToBytes(x,out,sizeBytes/2,(2*i+1)*sizeBytes/2-1);
            Utilities.longToBytes(y,out,sizeBytes/2,(2*i+2)*sizeBytes/2-1);
        }
        input=out;
//        printBytes(encryted);
//        return out;
//        return pad.removePKCS5Padding(out);
        return out;
    }
    byte[] decrypt(){
//        byte[] input=encryted;
        byte[] out=new byte[input.length];
        int l=input.length/sizeBytes;
        for(int i=0;i<l;i++){
            long x=Utilities.bytesToLong(input,2*i*sizeBytes/2,sizeBytes/2);
            long y=Utilities.bytesToLong(input,(2*i+1)*sizeBytes/2,sizeBytes/2);
//            System.out.println(x+" "+y);
            for(int j=r-1;j>=0;j--){
                y=Utilities.rotateRight(x^y,beta,sizeBits/2);
                y&=mask;
                x=Utilities.rotateLeft(((x^keys[j])-y)&mask,alpha,sizeBits/2);
                x&=mask;
            }
//            System.out.println(x+" "+y);
            Utilities.longToBytes(x,out,sizeBytes/2,(2*i+1)*sizeBytes/2-1);
            Utilities.longToBytes(y,out,sizeBytes/2,(2*i+2)*sizeBytes/2-1);
        }
//        return out;
        return pad.removePKCS5Padding(out);
    }
    private static void printBytes(final byte[] data) {
        for (int i = 0; i < data.length; i++) {
            System.out.printf("%02X ", data[i]);
        }
        System.out.println();
    }
}
