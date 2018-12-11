#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

int allNum( char buf[] ){
	if(!buf){ return 0; }
	int i=0;
	while( buf[i] ){
		if( buf[i]<48 || buf[i]>57 ){
			return 0;
		}
		i++;
	}
	return 1;
}
int hasStr( char haystack[], char needle[] ){
    int hLen = 0, nLen = 0, i, j, found;
    
	/* Get length of strings */
    while ( haystack[hLen] ){ hLen++; }   
    while ( needle[nLen] ){ nLen++; }
    
    /* Outer loop haystack, inner loop needle */    
    for ( i = 0; i <= hLen - nLen; i++ ){
        for ( j = i; j < i + nLen; j++ ){
            found = 1;
            if (haystack[j] != needle[j - i]){
                found = 0;
                break;
            }
        }
        if ( found )
            return 1;
    }
    return 0;
}
int getWord( int pos, char line[], char buf[] ){
	int i, j=0, k=0, lastWasSpace=0;
	for (i=0; 1; i++ ){
		if( !line[i] ){
			buf[k]='\0';
			return i;
		}
		if( line[i]<(char)33 ){
			if( k ){
				buf[k]='\0';
				return i;
			}
			if( !lastWasSpace ){
				j++;
			}
			lastWasSpace=1;
		}
		else{
			lastWasSpace=0;
			if( j==pos ){
				buf[k]=line[i];
				k++;
			}
			else{
			}
		}
		if( k > 10 ){
			buf[k]='\0';
			return i;
		}
	}
	buf[k]='\0';
	return 0;
}
int searchAndDisp( char uq[], int pos, FILE *outfile ){
    char line[256];
    char buf[16];
    static unsigned int cur, last=0, 
		max=0, min=(unsigned int)-1, 
		count=0, pcount=0, slope=0, lastSlope=0, tState=0;
    
	FILE *infile;
	if ( ( infile=fopen("/proc/keys","r") ) ) {	//same as calling cat /proc/keys
		count++;
		while ( fgets( line, sizeof(line), infile ) ){//skip other keyrings; find keyring containing char uq[]
			if ( hasStr( line, uq ) &&  getWord( pos, line, buf ) ){//get data from 3rd item, the usage (pos=2)
				if( allNum( buf ) ){
					cur=atoi( buf );
					slope=( cur > last )? 1:0;
					if( cur < min ){				//track min, max over time
						min=cur;
					}
					if( cur > max ){
						max=cur;
					}
					if( slope!=lastSlope ){
						if( pcount%10==0 ){
							printf("==============================================min=%d,\t max=%d\n", min, max );
							if( outfile ){
								fprintf( outfile, "==============================================min=%d,\t max=%d\n", min, max );
							}
						}
						printf("%d\t slope=%d, tState=%d\n", count, slope, tState );
						if( outfile ){
							fprintf( outfile, "%d\t slope=%d, tState=%d\n", count, slope, tState );
						}
						pcount++;
						tState=0;
					}
					last=cur;
					lastSlope=slope;
					tState++;
				}
				else{
					printf("non-numeric: %s\n", buf );
					return 0;
				}
				fclose(infile);
				return 1;
			}
		}
	}
	return 0;
}
int main( int argc, char* argv[] ){
	int i=0;
	FILE *outfile;
	struct timespec tim, tim2;
	tim.tv_sec  = 0;
	//tim.tv_nsec = 500000000L;//500,000,000
	//tim.tv_nsec = 50000000L;//50,000,000
	tim.tv_nsec = 500;
	if( argc<2 ){
		printf( "need search string\n" );
		return 1;
	}
	if( !( outfile=fopen("keylog","w") ) ){
		perror( "outfile" );
		return 1;
	}
	while(1){
		if(10000<i++){return 0;}
		if( !searchAndDisp( argv[1], 2, outfile ) ){
			perror( "searchAndDisp returned 0" );
		}
		if( nanosleep(&tim , &tim2)<0 ){
			perror( "nanosleep" );
		}
	}
	return 0;
}
